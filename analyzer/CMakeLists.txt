spicy_add_analyzer(
    NAME OpenVPN
    PACKAGE_NAME OpenVPN
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
