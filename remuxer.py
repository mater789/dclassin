#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Remux captured .dcap files (from frida_capture.py) into playable MP4.

Converts raw AVPacket data (AVCC H.264 / raw AAC) into elementary streams,
then muxes them into MP4 using FFmpeg (if available) or a built-in MP4 muxer.
"""

import os
import sys
import struct
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Tuple, BinaryIO

logger = logging.getLogger("remuxer")

# -------------------------------------------------------------------
# ISOBMFF / MP4 constants
# -------------------------------------------------------------------
DCAP_MAGIC = b"DCAP"
PKT_MAGIC = b"PKT\x00"

# -------------------------------------------------------------------
# Bitstream helpers
# -------------------------------------------------------------------
def avcc_extract_sps_pps(extradata: bytes) -> Tuple[List[bytes], List[bytes]]:
    """
    Parse AVCDecoderConfigurationRecord (ISO 14496-15) to extract SPS and PPS.

    Format:
        1 byte  configurationVersion (=1)
        1 byte  AVCProfileIndication
        1 byte  profile_compatibility
        1 byte  AVCLevelIndication
        1 byte  lengthSizeMinusOne (mask 0x03, typically 3 for 4-byte lengths)
        1 byte  numOfSequenceParameterSets (mask 0x1F)
        for each SPS:
            2 bytes  sequenceParameterSetLength
            N bytes  sequenceParameterSetNALUnit
        1 byte  numOfPictureParameterSets
        for each PPS:
            2 bytes  pictureParameterSetLength
            N bytes  pictureParameterSetNALUnit
    """
    sps_list = []
    pps_list = []

    if len(extradata) < 7:
        return sps_list, pps_list

    try:
        # lengthSizeMinusOne at offset 4, lower 2 bits
        num_sps = extradata[5] & 0x1F
        pos = 6
        for _ in range(num_sps):
            if pos + 2 > len(extradata):
                break
            sps_len = struct.unpack(">H", extradata[pos:pos+2])[0]
            pos += 2
            if pos + sps_len > len(extradata):
                break
            sps_list.append(extradata[pos:pos+sps_len])
            pos += sps_len

        if pos >= len(extradata):
            return sps_list, pps_list
        num_pps = extradata[pos]
        pos += 1
        for _ in range(num_pps):
            if pos + 2 > len(extradata):
                break
            pps_len = struct.unpack(">H", extradata[pos:pos+2])[0]
            pos += 2
            if pos + pps_len > len(extradata):
                break
            pps_list.append(extradata[pos:pos+pps_len])
            pos += pps_len
    except Exception:
        pass

    return sps_list, pps_list


def avcc_to_annexb(packet_data: bytes) -> bytes:
    """Convert a single AVCC-format NAL unit packet to Annex B format."""
    # Each NAL unit is prefixed with a 4-byte big-endian length
    # Replace each with a 4-byte Annex B start code: 0x00 0x00 0x00 0x01
    result = bytearray()
    pos = 0
    nal_count = 0
    while pos + 4 <= len(packet_data):
        nal_len = struct.unpack(">I", packet_data[pos:pos+4])[0]
        pos += 4
        if nal_len == 0 or pos + nal_len > len(packet_data):
            break
        # Annex B start code: 3 or 4 bytes
        result.extend(b"\x00\x00\x00\x01")
        result.extend(packet_data[pos:pos+nal_len])
        pos += nal_len
        nal_count += 1

    if nal_count == 0:
        # No length-prefixed NAL units found — maybe already Annex B?
        return packet_data

    return bytes(result)


def build_adts_header(aac_packet_len: int, sample_rate: int = 44100,
                      channels: int = 2, profile: int = 1) -> bytes:
    """
    Build a 7-byte ADTS header for a raw AAC frame.
    profile: 0=Main, 1=LC, 2=SSR, 3=LTP
    """
    # Map sample rates to index
    sr_table = {96000: 0, 88200: 1, 64000: 2, 48000: 3, 44100: 4,
                32000: 5, 24000: 6, 22050: 7, 16000: 8, 12000: 9,
                11025: 10, 8000: 11, 7350: 12}
    sr_idx = sr_table.get(sample_rate, 4)  # default 44100

    total_len = aac_packet_len + 7  # ADTS header is 7 bytes

    header = bytearray(7)
    # Sync word 0xFFF
    header[0] = 0xFF
    header[1] = 0xF9  # 0xF0 | (0<<3) | (0<<2) | (0<<1) | 1 (MPEG-4, no CRC)
    # 0b00_01_0_0_01 = MPEG-4, sampling index upper 2 bits, private bit, channel config upper bits
    header[2] = ((profile & 0x03) << 6) | ((sr_idx & 0x0F) << 2) | ((channels & 0x07) >> 2)
    header[3] = ((channels & 0x07) << 6) | ((total_len >> 11) & 0x03)
    header[4] = (total_len >> 3) & 0xFF
    header[5] = ((total_len & 0x07) << 5) | 0x1F
    header[6] = 0xFC  # buffer fullness = 0x7FF, 2 AAC raw data blocks

    return bytes(header)


# -------------------------------------------------------------------
# .dcap file parser
# -------------------------------------------------------------------
class DCapReader:
    """Reads .dcap capture files and yields packets."""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.url = ""
        self.streams: List[Dict] = []
        self._f: Optional[BinaryIO] = None

    def __enter__(self):
        self._f = open(self.filepath, "rb")
        # Read header
        magic, version = struct.unpack("<4sI", self._f.read(8))
        if magic != DCAP_MAGIC:
            raise ValueError(f"Not a valid .dcap file (magic={magic!r})")
        # URL
        url_len = struct.unpack("<I", self._f.read(4))[0]
        self.url = self._f.read(url_len).decode("utf-8", errors="replace")
        # Streams
        stream_count = struct.unpack("<I", self._f.read(4))[0]
        for _ in range(stream_count):
            idx = struct.unpack("<i", self._f.read(4))[0]
            codec_type = struct.unpack("<i", self._f.read(4))[0]
            codec_id = struct.unpack("<i", self._f.read(4))[0]
            edata_len = struct.unpack("<I", self._f.read(4))[0]
            edata = self._f.read(edata_len) if edata_len > 0 else b""
            self.streams.append({
                "index": idx,
                "codec_type": codec_type,
                "codec_id": codec_id,
                "extradata": edata,
            })
        return self

    def __exit__(self, *args):
        if self._f:
            self._f.close()

    def packets(self):
        """Generator yielding (stream_index, pts, dts, data) tuples."""
        while True:
            header = self._f.read(28)  # 4s(magic) + i(si) + q(pts) + q(dts) + I(size)
            if len(header) < 28:
                break
            magic, si, pts, dts, size = struct.unpack("<4siqqI", header)
            if magic == b"END\x00":
                break
            if magic != PKT_MAGIC:
                # Skip to find next valid packet
                continue
            data = self._f.read(size)
            if len(data) < size:
                break
            yield (si, pts, dts, data)


# -------------------------------------------------------------------
# Remuxer
# -------------------------------------------------------------------
class Remuxer:
    """Convert .dcap capture file to playable MP4."""

    def __init__(self, dcap_path: str, output_path: Optional[str] = None):
        self.dcap_path = Path(dcap_path)
        self.output_path = Path(output_path) if output_path else \
            self.dcap_path.with_suffix(".mp4")
        self._temp_dir = self.output_path.parent / f"_remux_{self.dcap_path.stem}"

    def remux(self) -> bool:
        """Main entry: parse .dcap, write elementary streams, mux to MP4."""
        if not self.dcap_path.exists():
            logger.error("File not found: %s", self.dcap_path)
            return False

        self._temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            with DCapReader(str(self.dcap_path)) as reader:
                # Identify video and audio streams
                vid_stream = None
                aud_stream = None
                for st in reader.streams:
                    if st["codec_type"] == 0 and vid_stream is None:
                        vid_stream = st
                    elif st["codec_type"] == 1 and aud_stream is None:
                        aud_stream = st

                if not vid_stream and not aud_stream:
                    logger.error("No video or audio streams found")
                    return False

                # Write elementary streams
                vid_path = self._temp_dir / "video.h264"
                aud_path = self._temp_dir / "audio.aac"
                has_video = False
                has_audio = False

                if vid_stream:
                    has_video = self._write_video_es(reader, vid_stream, vid_path)
                if aud_stream:
                    has_audio = self._write_audio_es(reader, aud_stream, aud_path)

                if not has_video and not has_audio:
                    logger.error("No packets extracted")
                    return False

                # Mux with FFmpeg
                return self._ffmpeg_mux(vid_path if has_video else None,
                                        aud_path if has_audio else None,
                                        self.output_path)
        except Exception as exc:
            logger.error("Remux failed: %s", exc)
            return False
        finally:
            # Cleanup temp files
            if self._temp_dir.exists():
                shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _write_video_es(self, reader: DCapReader,
                        stream: Dict, out_path: Path) -> bool:
        """Write H.264 elementary stream (Annex B format)."""
        extradata = stream.get("extradata", b"")
        sps_list, pps_list = avcc_extract_sps_pps(extradata)

        if not sps_list:
            logger.warning("No SPS found in extradata — video may not play")

        with open(out_path, "wb") as f:
            # Write SPS and PPS NAL units with start codes
            for sps in sps_list:
                f.write(b"\x00\x00\x00\x01")
                f.write(sps)
            for pps in pps_list:
                f.write(b"\x00\x00\x00\x01")
                f.write(pps)

            packet_count = 0
            for si, pts, dts, data in reader.packets():
                if si != stream["index"]:
                    continue
                annexb = avcc_to_annexb(data)
                f.write(annexb)
                packet_count += 1

        logger.info("Video: %d packets -> %s", packet_count, out_path)
        return packet_count > 0

    def _write_audio_es(self, reader: DCapReader,
                        stream: Dict, out_path: Path) -> bool:
        """Write AAC elementary stream with ADTS headers."""
        with open(out_path, "wb") as f:
            packet_count = 0
            for si, pts, dts, data in reader.packets():
                if si != stream["index"]:
                    continue
                # Add ADTS header (7 bytes) to raw AAC frame
                adts = build_adts_header(len(data))
                f.write(adts)
                f.write(data)
                packet_count += 1

        logger.info("Audio: %d packets -> %s", packet_count, out_path)
        return packet_count > 0

    @staticmethod
    def _ffmpeg_mux(vid_path: Optional[Path], aud_path: Optional[Path],
                    out_path: Path) -> bool:
        """Use FFmpeg to mux elementary streams into MP4."""
        cmd = ["ffmpeg", "-y"]

        if vid_path and vid_path.exists():
            cmd += ["-f", "h264", "-i", str(vid_path)]
        if aud_path and aud_path.exists():
            cmd += ["-f", "aac", "-i", str(aud_path)]

        cmd += ["-c", "copy", "-movflags", "+faststart", str(out_path)]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if r.returncode == 0:
                logger.info("Remuxed: %s", out_path)
                return True
            logger.error("FFmpeg failed:\n%s", r.stderr[:800])
        except FileNotFoundError:
            logger.error("ffmpeg not found in PATH — install FFmpeg to remux")
        except subprocess.TimeoutExpired:
            logger.error("FFmpeg timed out")

        return False


# -------------------------------------------------------------------
# Standalone
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Remux .dcap capture files to MP4")
    parser.add_argument("dcap_file", help="Path to .dcap file")
    parser.add_argument("-o", "--output", help="Output MP4 path", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    remuxer = Remuxer(args.dcap_file, args.output)
    if remuxer.remux():
        print(f"Done: {remuxer.output_path}")
    else:
        print("Remux failed")
        sys.exit(1)
