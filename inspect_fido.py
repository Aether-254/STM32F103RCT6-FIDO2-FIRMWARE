import hid

found = False

for dev in hid.enumerate():
    usage_page = dev.get("usage_page") or 0
    usage = dev.get("usage") or 0
    product = dev.get("product_string") or ""

    if usage_page == 0xF1D0 and usage == 0x01:
        found = True
        print("=== FIDO HID FOUND ===")
        print(f"Product: {product}")
        print(f"VID: 0x{dev['vendor_id']:04X}")
        print(f"PID: 0x{dev['product_id']:04X}")
        print(f"Usage Page: 0x{usage_page:04X}")
        print(f"Usage: 0x{usage:02X}")
        print(f"Path: {dev['path']}")
        print()

if not found:
    print("No FIDO HID interface found.")
    print("STM32-related HID devices:")
    for dev in hid.enumerate():
        name = dev.get("product_string") or ""
        manufacturer = dev.get("manufacturer_string") or ""
        if "STM" in (name + manufacturer).upper():
            print(dev)
