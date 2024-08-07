project "curl"

dofile(_BUILD_DIR .. "/static_library.lua")

configuration { "*" }

uuid "1D8D1667-48BF-459C-B213-947920022E95"

defines {
  "CURL_DISABLE_LDAP=1",
  "CURL_STATICLIB=1",
  "BUILDING_LIBCURL=1",
}

includedirs {
  -- public
  "include",
  "lib",

  -- private
  _3RDPARTY_DIR .. "/zlib-ng",
}

files {
  "lib/**.h",
  "lib/**.c",
}

if (_PLATFORM_ANDROID) then
end

if (_PLATFORM_COCOA) then
  configuration { "*cat*" }
end

if (_PLATFORM_IOS) then
end

if (_PLATFORM_LINUX) then
  buildoptions {
    "-include lib/curl_config_linux.h", -- Force include of curl_setup header
  }

  includedirs {
    _3RDPARTY_DIR .. "/openssl/include"
  }
end

if (_PLATFORM_MACOS) then
  buildoptions {
    "-include lib/curl_config_macos.h", -- Force include of curl_setup header
  }
end

if (_PLATFORM_WINDOWS) then
  defines {
    "USE_SCHANNEL",
    "USE_WINDOWS_SSPI",
    "HAVE_LIBZ",
    "USE_ZLIB",
  }
  buildoptions {
    "/wd4996", -- disable deprecated GetVersionEx warnings
  }
end

if (_PLATFORM_WINUWP) then
end
