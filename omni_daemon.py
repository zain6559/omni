import asyncio
import serial
import serial.tools.list_ports
import time
import sys
import logging
from mcp.server.fastmcp import FastMCP

# Setup basic logging to catch hidden crashes
logging.basicConfig(filename='daemon_crash.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

try:
    mcp = FastMCP("OmniMTK_Hardware_Daemon")

    # Physical memory for hijacked ports
    device_lock = {
        "ser": None,
        "port_name": None
    }

    @mcp.tool()
    async def wait_for_mtk_device(timeout_sec: int = 15) -> str:
        """CRITICAL SKILL: Actively waits and polls for a MediaTek device."""
        def _poll():
            start_time = time.time()
            while (time.time() - start_time) < timeout_sec:
                ports = serial.tools.list_ports.comports()
                for port, desc, hwid in ports:
                    if "0E8D" in hwid or "MediaTek" in desc or "MTK" in desc:
                        mode = "[BROM MODE]" if "0003" in hwid else "[PRELOADER MODE]"
                        return f"TARGET ACQUIRED: {mode} detected on {port} | HWID: {hwid}"
                time.sleep(0.1)
            return f"TIMEOUT: No MTK device detected after {timeout_sec} seconds."
        return await asyncio.to_thread(_poll)

    @mcp.tool()
    async def hijack_and_hold(port: str, baudrate: int = 115200) -> str:
        """LETHAL ENGAGEMENT: Opens the COM port and KEEPS IT OPEN forever."""
        def _hijack():
            global device_lock
            if device_lock["ser"] and device_lock["ser"].is_open:
                return f"ALREADY LOCKED: Port {device_lock['port_name']} is hijacked."
            
            try:
                ser = serial.Serial(port, baudrate, timeout=1.0, write_timeout=1.0)
                device_lock["ser"] = ser
                device_lock["port_name"] = port
                
                ser.write(b'\x00' * 4) 
                ser.flush()
                return f"PORT HIJACKED: {port} is now locked. Device boot sequence HALTED."
            except Exception as e:
                return f"HIJACK FAILED: {str(e)}"
        return await asyncio.to_thread(_hijack)

    @mcp.tool()
    async def execute_locked_rw(hex_command: str, read_length: int = 8) -> str:
        """EXECUTION: Sends hex commands to the ALREADY LOCKED port."""
        def _rw():
            global device_lock
            ser = device_lock["ser"]
            
            if not ser or not ser.is_open:
                return "ERROR: No port is locked. Execute 'hijack_and_hold' first."
                
            try:
                clean_hex = hex_command.replace(" ", "").replace("0x", "")
                raw_bytes = bytes.fromhex(clean_hex)
                
                ser.write(raw_bytes)
                ser.flush()
                response = ser.read(read_length)
                
                if not response:
                    return "WARNING: Command sent, but no response read. Timeout."
                    
                return f"EXECUTION SUCCESS | Sent: {clean_hex} | Received: {response.hex().upper()}"
            except Exception as e:
                return f"HARDWARE CRASH during RW: {str(e)}"
        return await asyncio.to_thread(_rw)

    @mcp.tool()
    async def release_device() -> str:
        """SAFETY PROTOCOL: Closes the port so the user can disconnect the phone."""
        def _release():
            global device_lock
            if device_lock["ser"] and device_lock["ser"].is_open:
                port_name = device_lock["port_name"]
                device_lock["ser"].close()
                device_lock["ser"] = None
                device_lock["port_name"] = None
                return f"PORT RELEASED: {port_name} closed safely."
            return "PORT ALREADY CLOSED."
        return await asyncio.to_thread(_release)

    if __name__ == "__main__":
        # Standard ignition sequence
        mcp.run()

except Exception as fatal_error:
    logging.critical(f"FATAL SERVER CRASH: {str(fatal_error)}")
    sys.exit(1)