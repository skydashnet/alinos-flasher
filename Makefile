BUILD_DIR = build
INCLUDES = -Isrc/core -Isrc/gui
GUI_SRC = src/gui/alinos_flashtool.c

all: $(BUILD_DIR)/ALINOS-FlashTool.exe

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/ALINOS-FlashTool.exe: $(GUI_SRC) src/gui/alinos.rc $(BUILD_DIR)
	@echo "[*] Compiling ALINOS-FlashTool.exe (GUI)..."
	@cd src/gui && llvm-rc -no-preprocess alinos.rc
	@/tmp/opencode/zig/zig cc -target x86_64-windows-gnu -c -Os $(INCLUDES) $(GUI_SRC) -o src/gui/alinos_gui_x64.o
	@/tmp/opencode/zig/zig cc -target x86_64-windows-gnu -Wl,--subsystem,windows -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -Wl,-s -Os src/gui/alinos_gui_x64.o src/gui/alinos.res -o $(BUILD_DIR)/ALINOS-FlashTool.exe -lws2_32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32 -lshell32 -liphlpapi -lwininet
	@rm -f src/gui/*.o src/gui/*.res
	@if [ -f certs/skydashnet_cert.pem ] && [ -x /tmp/opencode/osslsigncode_bin ]; then \
		echo "[*] Signing Authenticode (SkydashNET) & RFC 3161 Timestamp..."; \
		/tmp/opencode/osslsigncode_bin sign \
			-certs certs/skydashnet_cert.pem \
			-key certs/skydashnet_key.pem \
			-n "ALINOS.NET FlashTool Pro by SkydashNET" \
			-i "https://alinos-dashboard.my.id" \
			-h sha256 \
			-ts http://timestamp.sectigo.com \
			-in $(BUILD_DIR)/ALINOS-FlashTool.exe \
			-out $(BUILD_DIR)/ALINOS-FlashTool-signed.exe >/dev/null 2>&1 && \
		mv $(BUILD_DIR)/ALINOS-FlashTool-signed.exe $(BUILD_DIR)/ALINOS-FlashTool.exe; \
	fi
	@echo "[OK] Build selesai: $(BUILD_DIR)/ALINOS-FlashTool.exe"

clean:
	rm -f $(BUILD_DIR)/*.exe src/gui/*.o src/gui/*.res

.PHONY: all clean
