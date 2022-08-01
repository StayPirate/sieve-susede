require [ "duplicate", "variables", "imap4flags", "include" ] ;

global [ "FLAG_DUPLICATED", "FLAG_BETA" ];

if duplicate {
    addflag "${FLAG_DUPLICATED}";
}