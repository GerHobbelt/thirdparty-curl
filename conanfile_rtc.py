from conans import ConanFile


class Curlonan(ConanFile):
    name = "curl"
    version = "8.9.1"
    url = "https://devtopia.esri.com/3rdparty/curl/tree/runtimecore"
    license = "https://curl.se/docs/copyright.html"
    description = "libcurl is a free and easy-to-use client-side URL transfer library"

    # RTC specific triple
    settings = "platform_architecture_target"

    def package(self):
        base = self.source_folder + "/"
        relative = "3rdparty/curl/"

        # headers
        self.copy("*.h", src=base, dst=relative)

        # libraries
        output = "output/" + str(self.settings.platform_architecture_target) + "/staticlib"
        self.copy("*" + self.name + "*", src=base + "../../" + output, dst=output)