rule RULE_NAME {
    meta:
        author = "YOUR_NAME"
        create_date = "YYYY-MM-DD"
        modified_date = "YYYY-MM-DD"
        hash1 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        hash2 = "0c61e11f4b056f9866f41c8d5b7f89f8892e44dbeaa0e03bd65a4cf81ce4dcb7"
        hash3 = "7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0"
        hash4 = "abf9adf2c2c21c1e8bd69975dfccb5ca53060d8e1e7271a5e9ef3b56a7e54d9f"
        hash5 = "afe1f2768e57573757039a40ac40f3c7471bb084599613b3402b1e9958e0d27a"
        description = ""
    strings:
        $s1 = "ADD YOUR SIGNATURE HERE"
    condition:
        uint16(0) == 0x5a4d and // MZ
        uint32(uint32(0x3c)) == 0x00004550 and //PE
        all of them // REPLACE HERE
}