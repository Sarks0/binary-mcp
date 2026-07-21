"""
WinDbg text output parser.

Converts raw CDB/KD text output from extension commands (! commands) into
structured Python objects. Used only for WinDbg commands that have no
DbgEng COM API equivalent.
"""

import re

from src.engines.dynamic.windbg.kernel_types import (
    CrashAnalysis,
    DeviceObject,
    DriverObject,
    IOCTLCode,
    PoolAllocation,
)


class WinDbgOutputParser:
    """Static methods for parsing WinDbg text command output."""

    @staticmethod
    def parse_registers(output: str) -> dict[str, str]:
        """Parse 'r' command output into register name-value pairs.

        Handles formats like:
            rax=0000000000000001 rbx=00007ff6a1b20000
            efl=00000246

        Args:
            output: Raw text from the 'r' command.

        Returns:
            Dictionary mapping register names to hex value strings.
        """
        registers: dict[str, str] = {}
        for match in re.finditer(r"(\w+)=([0-9a-fA-F]+)", output):
            registers[match.group(1)] = match.group(2)
        return registers

    @staticmethod
    def parse_modules(output: str) -> list[dict[str, str]]:
        """Parse 'lm' command output into module records.

        Handles formats like:
            fffff800`12340000 fffff800`12350000   nt  (pdb symbols) ...
            00007ff6`a1b20000 00007ff6`a1b40000   notepad  (deferred)

        Args:
            output: Raw text from the 'lm' command.

        Returns:
            List of dicts with keys: start, end, name, symbol_status.
        """
        modules: list[dict[str, str]] = []
        pattern = re.compile(
            r"([0-9a-fA-F`]+)\s+"
            r"([0-9a-fA-F`]+)\s+"
            r"(\S+)\s+"
            r"(?:\(([^)]*)\))?"
        )
        for match in pattern.finditer(output):
            modules.append({
                "start": match.group(1).replace("`", ""),
                "end": match.group(2).replace("`", ""),
                "name": match.group(3),
                "symbol_status": match.group(4) or "unknown",
            })
        return modules

    @staticmethod
    def parse_stack(output: str) -> list[dict[str, str]]:
        """Parse 'k'/'kp' command output into stack frames.

        Handles formats like:
            # Child-SP          RetAddr           Call Site
            00 fffff800`1234abcd fffff800`5678efab nt!KeBugCheckEx+0x0
            01 fffff800`1234abd0 fffff800`5678efcd module!Func+0x42

        Args:
            output: Raw text from the 'k' or 'kp' command.

        Returns:
            List of dicts with keys: frame, child_sp, ret_addr, call_site.
        """
        frames: list[dict[str, str]] = []
        pattern = re.compile(
            r"([0-9a-fA-F]+)\s+"
            r"([0-9a-fA-F`]+)\s+"
            r"([0-9a-fA-F`]+)\s+"
            r"(.+)"
        )
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Child"):
                continue
            match = pattern.match(line)
            if match:
                frames.append({
                    "frame": match.group(1),
                    "child_sp": match.group(2).replace("`", ""),
                    "ret_addr": match.group(3).replace("`", ""),
                    "call_site": match.group(4).strip(),
                })
        return frames

    @staticmethod
    def parse_disassembly(output: str) -> list[dict[str, str]]:
        """Parse 'u addr L10' disassembly output.

        Handles formats like:
            nt!KeBugCheckEx:
            fffff800`12340000 4883ec28        sub     rsp,28h
            fffff800`12340004 488bc1          mov     rax,rcx

        Args:
            output: Raw text from the 'u' command.

        Returns:
            List of dicts with keys: address, bytes, instruction.
        """
        instructions: list[dict[str, str]] = []
        pattern = re.compile(
            r"([0-9a-fA-F`]+)\s+"
            r"([0-9a-fA-F]+)\s+"
            r"(.+)"
        )
        for line in output.splitlines():
            line = line.strip()
            if not line or line.endswith(":"):
                continue
            match = pattern.match(line)
            if match:
                instructions.append({
                    "address": match.group(1).replace("`", ""),
                    "bytes": match.group(2),
                    "instruction": match.group(3).strip(),
                })
        return instructions

    @staticmethod
    def parse_memory_dump(output: str) -> bytes:
        """Parse 'db addr' hex dump output into raw bytes.

        Handles formats like:
            fffff800`12340000  48 83 ec 28 48 8b c1 48-8b d1 e8 00 00 00 00 c3  H...(H..H......

        Args:
            output: Raw text from the 'db' command.

        Returns:
            Raw bytes extracted from the hex dump.
        """
        raw_bytes = bytearray()
        pattern = re.compile(
            r"[0-9a-fA-F`]+\s+"
            r"((?:[0-9a-fA-F]{2}[\s\-])+)"
        )
        for match in pattern.finditer(output):
            hex_part = match.group(1).replace("-", " ")
            for hex_byte in hex_part.split():
                hex_byte = hex_byte.strip()
                if hex_byte and len(hex_byte) == 2:
                    raw_bytes.append(int(hex_byte, 16))
        return bytes(raw_bytes)

    @staticmethod
    def parse_driver_object(output: str) -> DriverObject:
        """Parse '!drvobj \\Driver\\Name 3' output including dispatch table.

        Handles formats like:
            Driver object (fffff80012340000) is for:
             \\Driver\\TestDriver
            Driver Extension List: (id, addr)
            (fffff80012350000, fffff80012360000)
            Device Object list:
            fffff80012370000
            Dispatch routines:
            [00] IRP_MJ_CREATE                  fffff80012380000  module!CreateDispatch
            [01] IRP_MJ_CLOSE                   fffff80012380100  module!CloseDispatch

        Args:
            output: Raw text from '!drvobj' with verbosity 3.

        Returns:
            DriverObject populated from parsed output.
        """
        # Extract driver address
        addr_match = re.search(r"Driver object \(([0-9a-fA-F`]+)\)", output)
        address = addr_match.group(1).replace("`", "") if addr_match else "0"

        # Extract driver name
        name_match = re.search(r"\\Driver\\(\S+)", output)
        name = name_match.group(0) if name_match else "unknown"

        # Extract device objects
        device_objects: list[str] = []
        in_device_list = False
        for line in output.splitlines():
            stripped = line.strip()
            if "Device Object list:" in line:
                in_device_list = True
                continue
            if in_device_list:
                dev_match = re.match(r"([0-9a-fA-F`]+)\s*$", stripped)
                if dev_match:
                    device_objects.append(dev_match.group(1).replace("`", ""))
                elif stripped and not stripped.startswith("("):
                    in_device_list = False

        # Extract dispatch table
        dispatch_table: dict[str, str] = {}
        dispatch_pattern = re.compile(
            r"\[[0-9a-fA-F]+\]\s+(IRP_MJ_\w+)\s+([0-9a-fA-F`]+)"
        )
        for match in dispatch_pattern.finditer(output):
            dispatch_table[match.group(1)] = match.group(2).replace("`", "")

        # Extract driver extension
        ext_match = re.search(
            r"Driver Extension List:.*?\(([0-9a-fA-F`]+)", output, re.DOTALL
        )
        driver_extension = (
            ext_match.group(1).replace("`", "") if ext_match else None
        )

        # Extract driver start and size
        start_match = re.search(r"start\s+([0-9a-fA-F`]+)", output, re.IGNORECASE)
        size_match = re.search(r"size\s+([0-9a-fA-F]+)", output, re.IGNORECASE)

        return DriverObject(
            name=name,
            address=address,
            device_objects=device_objects,
            dispatch_table=dispatch_table,
            driver_start=start_match.group(1).replace("`", "") if start_match else None,
            driver_size=int(size_match.group(1), 16) if size_match else None,
            driver_extension=driver_extension,
        )

    @staticmethod
    def parse_device_object(output: str) -> DeviceObject:
        """Parse '!devobj addr' output.

        Handles formats like:
            Device object (fffff80012370000) is for:
             TestDevice \\Driver\\TestDriver
            Device Type: 00000022
            Flags: 00000040
            AttachedTo (Lower) fffff80012380000

        Args:
            output: Raw text from '!devobj'.

        Returns:
            DeviceObject populated from parsed output.
        """
        # Extract device address
        addr_match = re.search(r"Device object \(([0-9a-fA-F`]+)\)", output)
        address = addr_match.group(1).replace("`", "") if addr_match else "0"

        # Extract driver reference
        driver_match = re.search(r"\\Driver\\(\S+)", output)
        driver_object = driver_match.group(0) if driver_match else "unknown"

        # Extract device type
        type_match = re.search(r"Device\s*Type:\s*([0-9a-fA-F]+)", output, re.IGNORECASE)
        device_type = int(type_match.group(1), 16) if type_match else 0

        # Extract device name (first token on the "is for:" line after the address line)
        name_match = re.search(
            r"Device object.*?is for:\s*\n\s*(\S+)", output, re.DOTALL
        )
        device_name = name_match.group(1) if name_match else None
        # Filter out if it looks like a driver path rather than a device name
        if device_name and device_name.startswith("\\Driver\\"):
            device_name = None

        # Extract flags
        flags_match = re.search(r"Flags:\s*([0-9a-fA-F]+)", output, re.IGNORECASE)
        flags = int(flags_match.group(1), 16) if flags_match else 0

        # Extract attached device (at least 8 hex digits to avoid matching words)
        attached_match = re.search(
            r"AttachedTo.*?([0-9a-fA-F`]{8,})", output, re.IGNORECASE
        )
        attached_to = (
            attached_match.group(1).replace("`", "") if attached_match else None
        )

        return DeviceObject(
            address=address,
            driver_object=driver_object,
            device_type=device_type,
            device_name=device_name,
            attached_to=attached_to,
            flags=flags,
        )

    @staticmethod
    def parse_pool_info(output: str) -> PoolAllocation:
        """Parse '!pool addr' output.

        Handles formats like:
            Pool page fffff80012340000 region is Nonpaged pool
             fffff80012340000 size:  100 previous size:    0  (Allocated)  Ntfs
                 Pooltag Ntfs : NTFS general allocation, Binary : ntfs.sys

        Args:
            output: Raw text from '!pool'.

        Returns:
            PoolAllocation populated from parsed output.
        """
        # Extract address
        addr_match = re.search(
            r"Pool page\s+([0-9a-fA-F`]+)", output, re.IGNORECASE
        )
        address = addr_match.group(1).replace("`", "") if addr_match else "0"

        # Extract pool type
        pool_type = "unknown"
        if re.search(r"Nonpaged pool", output, re.IGNORECASE):
            pool_type = "NonPaged"
        elif re.search(r"Paged pool", output, re.IGNORECASE):
            pool_type = "Paged"

        # Extract size (hex)
        size_match = re.search(r"size:\s+([0-9a-fA-F]+)", output, re.IGNORECASE)
        size = int(size_match.group(1), 16) if size_match else 0

        # Extract pool tag
        tag_match = re.search(r"Pooltag\s+(\S+)", output, re.IGNORECASE)
        if not tag_match:
            tag_match = re.search(r"\(Allocated\)\s+(\S+)", output)
        tag = tag_match.group(1) if tag_match else "????"

        # Extract owning component (Binary : xxx.sys)
        component_match = re.search(r"Binary\s*:\s*(\S+)", output, re.IGNORECASE)
        owning_component = component_match.group(1) if component_match else None

        return PoolAllocation(
            address=address,
            tag=tag,
            size=size,
            pool_type=pool_type,
            owning_component=owning_component,
        )

    @staticmethod
    def parse_analyze(output: str) -> CrashAnalysis:
        """Parse '!analyze -v' output for crash dump analysis.

        This is the most complex parser, handling the verbose analysis output
        that includes bugcheck code, arguments, faulting module, stack trace,
        and probable cause.

        Args:
            output: Raw text from '!analyze -v'.

        Returns:
            CrashAnalysis populated from parsed output.
        """
        # Extract bugcheck code and name
        bugcheck_match = re.search(
            r"BugCheck\s+([0-9a-fA-F]+)\s*\{", output, re.IGNORECASE
        )
        bugcheck_code = (
            int(bugcheck_match.group(1), 16) if bugcheck_match else 0
        )

        name_match = re.search(
            r"BUGCHECK_STR:\s*(.+)", output, re.IGNORECASE
        )
        if not name_match:
            name_match = re.search(
                r"([A-Z_]+)\s*\(\s*[0-9a-fA-F]+\s*\)", output
            )
        bugcheck_name = name_match.group(1).strip() if name_match else "UNKNOWN"

        # Extract bugcheck arguments from { arg1, arg2, arg3, arg4 }
        args_match = re.search(
            r"\{\s*([0-9a-fA-F`]+)\s*,\s*([0-9a-fA-F`]+)\s*,"
            r"\s*([0-9a-fA-F`]+)\s*,\s*([0-9a-fA-F`]+)\s*\}",
            output,
        )
        arguments: list[str] = []
        if args_match:
            arguments = [
                g.replace("`", "") for g in args_match.groups()
            ]

        # Extract faulting module
        module_match = re.search(
            r"MODULE_NAME:\s*(\S+)", output, re.IGNORECASE
        )
        if not module_match:
            module_match = re.search(
                r"IMAGE_NAME:\s*(\S+)", output, re.IGNORECASE
            )
        faulting_module = module_match.group(1) if module_match else None

        # Extract faulting address
        fault_addr_match = re.search(
            r"FAULTING_IP:\s*\n?\s*\S+\+\S+\s*\n?\s*([0-9a-fA-F`]+)",
            output,
            re.IGNORECASE,
        )
        if not fault_addr_match:
            fault_addr_match = re.search(
                r"DEFAULT_BUCKET_ID:.*?FAILURE_ADDRESS:\s*([0-9a-fA-F`]+)",
                output,
                re.DOTALL | re.IGNORECASE,
            )
        faulting_address = (
            fault_addr_match.group(1).replace("`", "")
            if fault_addr_match
            else None
        )

        # Extract stack trace lines
        stack_trace: list[str] = []
        in_stack = False
        for line in output.splitlines():
            stripped = line.strip()
            if re.match(r"STACK_TEXT:", stripped, re.IGNORECASE):
                in_stack = True
                continue
            if in_stack:
                if not stripped or stripped.startswith("FOLLOWUP") or ":" in stripped[:30]:
                    # End of stack section when we hit another label
                    if re.match(r"[A-Z_]+:", stripped):
                        break
                if stripped:
                    stack_trace.append(stripped)

        # Extract probable cause
        cause_match = re.search(
            r"FOLLOWUP_NAME:\s*(.+)", output, re.IGNORECASE
        )
        if not cause_match:
            cause_match = re.search(
                r"FAILURE_BUCKET_ID:\s*(.+)", output, re.IGNORECASE
            )
        probable_cause = cause_match.group(1).strip() if cause_match else None

        return CrashAnalysis(
            bugcheck_code=bugcheck_code,
            bugcheck_name=bugcheck_name,
            arguments=arguments,
            faulting_module=faulting_module,
            faulting_address=faulting_address,
            stack_trace=stack_trace,
            probable_cause=probable_cause,
        )

    @staticmethod
    def parse_ioctl_decode(output: str) -> IOCTLCode:
        """Parse '!ioctldecode code' output or decode from raw hex.

        Handles formats like:
            Device Type    : 0x0022 (FILE_DEVICE_UNKNOWN)
            Method         : 0x3 (METHOD_NEITHER)
            Access         : FILE_ANY_ACCESS
            Function       : 0x803

        Falls back to IOCTLCode.decode() if a raw hex code is found.

        Args:
            output: Raw text from '!ioctldecode'.

        Returns:
            IOCTLCode populated from parsed output.
        """
        device_match = re.search(
            r"Device\s*Type\s*:\s*0x([0-9a-fA-F]+)", output, re.IGNORECASE
        )
        method_match = re.search(
            r"Method\s*:\s*0x([0-9a-fA-F]+)", output, re.IGNORECASE
        )
        func_match = re.search(
            r"Function\s*:\s*0x([0-9a-fA-F]+)", output, re.IGNORECASE
        )
        access_match = re.search(
            r"Access\s*:\s*(\S+)", output, re.IGNORECASE
        )

        # If all fields are present, build directly
        if device_match and method_match and func_match:
            device_type = int(device_match.group(1), 16)
            method = int(method_match.group(1), 16)
            function_code = int(func_match.group(1), 16)

            # Map access string to numeric value
            access = 0
            if access_match:
                access_str = access_match.group(1).upper()
                access_map = {
                    "FILE_ANY_ACCESS": 0,
                    "FILE_READ_ACCESS": 1,
                    "FILE_WRITE_ACCESS": 2,
                    "FILE_READ_DATA": 1,
                    "FILE_WRITE_DATA": 2,
                }
                access = access_map.get(access_str, 0)
                # Handle combined read+write
                if "READ" in access_str and "WRITE" in access_str:
                    access = 3

            # Reconstruct raw code
            raw_code = (
                (device_type << 16)
                | (access << 14)
                | (function_code << 2)
                | method
            )

            return IOCTLCode.decode(raw_code)

        # Fallback: find a raw hex IOCTL code in the output
        raw_match = re.search(r"0x([0-9a-fA-F]{6,8})", output)
        if raw_match:
            return IOCTLCode.decode(int(raw_match.group(1), 16))

        return IOCTLCode(
            raw_code=0,
            device_type=0,
            function_code=0,
            method=0,
            access=0,
            risk_level="unknown",
        )

    @staticmethod
    def parse_processes(output: str) -> list[dict[str, str]]:
        """Parse '!process 0 0' output into process records.

        Handles formats like:
            PROCESS fffff80012340000
                SessionId: 1  Cid: 0004    Peb: 00000000  ParentCid: 0000
                DirBase: 001aa000  ObjectTable: ffff9c0123450000  HandleCount: 1234
                Image: System

            PROCESS fffff80012350000
                SessionId: 1  Cid: 01a8    Peb: 7ffd0000  ParentCid: 0004
                Image: smss.exe

        Args:
            output: Raw text from '!process 0 0'.

        Returns:
            List of dicts with keys: address, session_id, pid, ppid, image.
        """
        processes: list[dict[str, str]] = []
        current: dict[str, str] | None = None

        for line in output.splitlines():
            stripped = line.strip()

            # New process block
            proc_match = re.match(
                r"PROCESS\s+([0-9a-fA-F`]+)", stripped, re.IGNORECASE
            )
            if proc_match:
                if current:
                    processes.append(current)
                current = {
                    "address": proc_match.group(1).replace("`", ""),
                    "session_id": "",
                    "pid": "",
                    "ppid": "",
                    "image": "",
                }
                continue

            if current is None:
                continue

            # Parse session and CID (process ID)
            cid_match = re.search(
                r"SessionId:\s*(\S+)\s+Cid:\s*([0-9a-fA-F]+)", stripped
            )
            if cid_match:
                current["session_id"] = cid_match.group(1)
                current["pid"] = cid_match.group(2)

            # Parse parent CID
            parent_match = re.search(r"ParentCid:\s*([0-9a-fA-F]+)", stripped)
            if parent_match:
                current["ppid"] = parent_match.group(1)

            # Parse image name
            image_match = re.search(r"Image:\s*(\S+)", stripped)
            if image_match:
                current["image"] = image_match.group(1)

        # Append last process
        if current:
            processes.append(current)

        return processes
