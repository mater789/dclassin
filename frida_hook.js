/**
 * Frida hook for ClassIn — intercepts video URL + packet data from FFmpeg.
 *
 * Hooks avformat_open_input and av_read_frame in avformat-58.dll.
 * Data is already decrypted at this layer (post-TLS, pre-codec).
 *
 * Compatible with Frida 17.x API:
 *   Process.getModuleByName(name).getExportByName(name)
 *
 * AVPacket layout (FFmpeg 4.x, x64):
 *   buf              @  0  (AVBufferRef*)
 *   pts              @  8  (int64_t)
 *   dts              @ 16  (int64_t)
 *   data             @ 24  (uint8_t*)
 *   size             @ 32  (int32_t)
 *   stream_index     @ 36  (int32_t)
 *   flags            @ 40  (int32_t)
 *   side_data        @ 48  (AVPacketSideData*)
 *   side_data_elems  @ 56  (int32_t)
 *   duration         @ 64  (int64_t)
 *   pos              @ 72  (int64_t)
 *
 * AVCodecParameters (FFmpeg 4.x, x64):
 *   codec_type       @  0  (int32_t)  0=video, 1=audio, 2=subtitle
 *   codec_id         @  4  (int32_t)
 *   extradata        @ 32  (uint8_t*)
 *   extradata_size   @ 40  (int32_t)
 */

(function() {
    "use strict";

    var sessionCount = 0;
    var pktCount = 0;
    var captureActive = false;
    var DLL_NAME = "avformat-58.dll";

    // -------------------------------------------------------------------
    // Safe memory readers
    // -------------------------------------------------------------------
    function readCStr(ptr) {
        try { if (ptr && !ptr.isNull()) return ptr.readCString(); } catch(e) {}
        return null;
    }

    function readS32(ptr) {
        try { return ptr.readS32(); } catch(e) { return 0; }
    }

    function readU32(ptr) {
        try { return ptr.readU32(); } catch(e) { return 0; }
    }

    function readPtr(ptr) {
        try { if (ptr && !ptr.isNull()) return ptr.readPointer(); } catch(e) {}
        return null;
    }

    // -------------------------------------------------------------------
    // Get export from DLL (Frida 17.x compatible)
    // -------------------------------------------------------------------
    function getExport(dllName, funcName) {
        try {
            var mod = Process.getModuleByName(dllName);
            return mod.getExportByName(funcName);
        } catch(e) {
            return null;
        }
    }

    // -------------------------------------------------------------------
    // Stream info extraction from AVFormatContext
    // -------------------------------------------------------------------
    function extractStreamInfo(ctxPtrPtr) {
        var ctx = readPtr(ctxPtrPtr);
        if (!ctx) return [];

        // Probe nb_streams at version-dependent offsets
        var nbStreams = 0;
        var streamsPtr = null;
        var offsets = [0x78, 0x74, 0x30, 0x34, 0x80, 0x70, 0x6C, 0x7C];
        for (var i = 0; i < offsets.length; i++) {
            var n = readU32(ctx.add(offsets[i]));
            if (n > 0 && n <= 20) {
                var sp = readPtr(ctx.add(offsets[i] + 4));
                if (sp) { nbStreams = n; streamsPtr = sp; break; }
                sp = readPtr(ctx.add(offsets[i] + 8));
                if (sp) { nbStreams = n; streamsPtr = sp; break; }
            }
        }
        if (!nbStreams || !streamsPtr) return [];

        var streams = [];
        for (var i = 0; i < nbStreams; i++) {
            try {
                var stream = readPtr(streamsPtr.add(i * 8));
                if (!stream) continue;

                var codecpar = null;
                var cpOffsets = [0x78, 0x80, 0x88, 0x70, 0x90, 0x98, 0xA0, 0xA8];
                for (var j = 0; j < cpOffsets.length; j++) {
                    var cp = readPtr(stream.add(cpOffsets[j]));
                    if (cp) {
                        var t = readS32(cp);
                        if (t >= 0 && t <= 5) { codecpar = cp; break; }
                    }
                }
                if (!codecpar) continue;

                var codecType = readS32(codecpar);
                var codecId = readS32(codecpar.add(4));
                var extradataPtr = readPtr(codecpar.add(32));
                var extradataSize = readS32(codecpar.add(40));

                var extradataB64 = null;
                if (extradataPtr && extradataSize > 0 && extradataSize < 1048576) {
                    try {
                        extradataB64 = btoa(
                            String.fromCharCode.apply(null,
                                new Uint8Array(extradataPtr.readByteArray(extradataSize))
                            )
                        );
                    } catch(e) {}
                }

                streams.push({
                    index: i,
                    codec_type: codecType,
                    codec_id: codecId,
                    extradata_b64: extradataB64,
                    extradata_size: extradataSize
                });
            } catch(e) {}
        }
        return streams;
    }

    // -------------------------------------------------------------------
    // Hook installer — waits for DLL if not yet loaded
    // -------------------------------------------------------------------
    function installHooks() {
        // Check if DLL is loaded
        try {
            Process.getModuleByName(DLL_NAME);
        } catch(e) {
            send({type: "status", msg: "Waiting for " + DLL_NAME + " to load..."});
            // Poll until loaded
            var attempts = 0;
            var timer = setInterval(function() {
                attempts++;
                try {
                    Process.getModuleByName(DLL_NAME);
                    clearInterval(timer);
                    doInstall();
                } catch(e) {
                    if (attempts > 300) { // 60 seconds
                        clearInterval(timer);
                        send({type: "error", msg: "Timeout waiting for " + DLL_NAME});
                    }
                }
            }, 200);
            return;
        }
        doInstall();
    }

    function doInstall() {
        // --- avformat_open_input ---
        var openInput = getExport(DLL_NAME, "avformat_open_input");
        if (openInput) {
            Interceptor.attach(openInput, {
                onEnter: function(args) {
                    var url = readCStr(args[1]);
                    if (url && url.length > 5) {
                        sessionCount++;
                        pktCount = 0;
                        captureActive = true;
                        send({type: "url", url: url, sid: sessionCount});
                    }
                    this._sid = sessionCount;
                    this._ctxPtrPtr = args[0];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) return;
                    var streams = extractStreamInfo(this._ctxPtrPtr);
                    if (streams.length > 0) {
                        send({type: "streams", sid: this._sid, streams: streams});
                    }
                }
            });
            send({type: "ready", fn: "avformat_open_input"});
        } else {
            send({type: "error", msg: "avformat_open_input not found"});
        }

        // --- av_read_frame ---
        var readFrame = getExport(DLL_NAME, "av_read_frame");
        if (readFrame) {
            var readFrameTotalCalls = 0;
            Interceptor.attach(readFrame, {
                onEnter: function(args) {
                    this._pkt = args[1];
                },
                onLeave: function(retval) {
                    readFrameTotalCalls++;
                    if (retval.toInt32() !== 0) return;

                    // Debug: log first few calls and periodic stats
                    if (readFrameTotalCalls <= 3 || readFrameTotalCalls % 300 === 0) {
                        send({type: "debug", msg: "av_read_frame call #" + readFrameTotalCalls + " active=" + captureActive});
                    }

                    if (!captureActive) return;

                    try {
                        var p = this._pkt;
                        var dataPtr = p.add(24).readPointer();
                        var size = p.add(32).readU32();
                        var si = p.add(36).readS32();
                        var pts = p.add(8).readS64();
                        var dts = p.add(16).readS64();

                        if (size > 0 && size < 5242880 && !dataPtr.isNull()) {
                            var raw = dataPtr.readByteArray(size);
                            if (raw) {
                                pktCount++;
                                send({
                                    type: "pkt",
                                    si: si,
                                    pts: pts.toString(),
                                    dts: dts.toString(),
                                    sz: size,
                                    n: pktCount
                                }, raw);
                            }
                        }
                    } catch(e) {}
                }
            });
            send({type: "ready", fn: "av_read_frame"});
        } else {
            send({type: "error", msg: "av_read_frame not found"});
        }

        // --- avformat_close_input ---
        var closeInput = getExport(DLL_NAME, "avformat_close_input");
        if (closeInput) {
            Interceptor.attach(closeInput, {
                onLeave: function(retval) {
                    if (captureActive) {
                        send({type: "end", pkt_count: pktCount});
                        captureActive = false;
                    }
                }
            });
            send({type: "ready", fn: "avformat_close_input"});
        }

        send({type: "hooks_installed"});
    }

    // -------------------------------------------------------------------
    // Start
    // -------------------------------------------------------------------
    installHooks();
})();
