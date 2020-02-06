/*
 * Copyright 2019, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   wiltoncall_winscm.cpp
 * Author: alex
 *
 * Created on November 22, 2019, 5:24 PM
 */

#include <functional>
#include <string>

#include "staticlib/support/windows.hpp"

#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/registrar.hpp"

namespace wilton {
namespace winscm {

namespace { //anonymous

const std::string logger = std::string("wilton.winscm");

std::string status_str(DWORD status) STATICLIB_NOEXCEPT {
    switch (status) {
    case SERVICE_RUNNING: return "SERVICE_RUNNING";
    case SERVICE_START_PENDING: return "SERVICE_START_PENDING";
    case SERVICE_STOP_PENDING: return "SERVICE_STOP_PENDING";
    case SERVICE_STOPPED: return "SERVICE_STOPPED";
    default: return sl::support::to_string(status);
    }
}

bool set_service_status(SERVICE_STATUS_HANDLE ha, DWORD status) STATICLIB_NOEXCEPT {
    SERVICE_STATUS st;
    std::memset(std::addressof(st), '\0', sizeof(st));
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState = status;
    st.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    st.dwWin32ExitCode = NO_ERROR;
    st.dwServiceSpecificExitCode = 0;
    st.dwWaitHint = 0;
    
    if (SERVICE_RUNNING == status || SERVICE_STOPPED == status) {
        st.dwCheckPoint = 0;
    } else {
        st.dwCheckPoint = 1;
    }
    auto success = ::SetServiceStatus(ha, std::addressof(st));
    if (0 == success) {
        wilton::support::log_error(logger, std::string(
                "Error changing status to: [" + status_str(status) + "],") +
                " error: [" + sl::utils::errcode_to_string(::GetLastError()) + "]");
        return false;
    }
    wilton::support::log_debug(logger, "SCM service status changed, value: [" + status_str(status) + "]");
    return true;
}

DWORD WINAPI service_control_handler(DWORD step, DWORD, LPVOID, LPVOID ha_ptr) STATICLIB_NOEXCEPT {
    auto ha = *reinterpret_cast<SERVICE_STATUS_HANDLE*>(ha_ptr);
    switch (step) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN: {
        auto success_pending = set_service_status(ha, SERVICE_STOP_PENDING);
        if (success_pending) {
            auto success = set_service_status(ha, SERVICE_STOPPED);
            (void) success;
        }
        break;
    }
    default: break;
    }
    return NO_ERROR;
}

void WINAPI service_main(DWORD, LPWSTR* args) STATICLIB_NOEXCEPT {
    // The first parameter contains the number of arguments being passed to the service in the second parameter.
    // There will always be at least one argument. The second parameter is a pointer to an array of string pointers.
    // The first item in the array is always the service name.
    auto name = args[0];
    // this pointer is leaked only once on startup
    SERVICE_STATUS_HANDLE* ha_ptr = static_cast<SERVICE_STATUS_HANDLE*>(malloc(sizeof(SERVICE_STATUS_HANDLE*)));
    *ha_ptr = nullptr;

    // register the handler function for the service
    wilton::support::log_debug(logger, "Is due to register service control handler ...");
    auto ha = ::RegisterServiceCtrlHandlerExW(name, service_control_handler, reinterpret_cast<LPVOID>(ha_ptr));
    if (nullptr == ha) {
        wilton::support::log_error(logger, std::string("Fatal error on RegisterServiceCtrlHandlerExW,") +
                " message: [" + sl::utils::errcode_to_string(::GetLastError()) + "]");
        return;
    }
    wilton::support::log_debug(logger, "Service control handler registered");
    *ha_ptr = ha;
    auto success_pending = set_service_status(ha, SERVICE_START_PENDING);
    if (success_pending) {
        auto success = set_service_status(ha, SERVICE_RUNNING);
        if (success) {
            wilton::support::log_info(logger, "SCM service started");
        }
    }
}

} // namespace

support::buffer start_service_control_dispatcher(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rname = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("name" == name) {
            rname = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rname.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'name' not specified"));
    const std::string& name = rname.get();

    // call SCM
    wilton::support::log_debug(logger, std::string("Is due to call SCM,") +
            " service name: [" + name + "]");
    auto wname = sl::utils::widen(name);
    SERVICE_TABLE_ENTRYW st[] = {
        { std::addressof(wname.front()), service_main },
        { nullptr, nullptr }
    };

    // Connects the main thread of a service process to the service control 
    // manager, which causes the thread to be the service control dispatcher 
    // thread for the calling process. This call returns when the service has 
    // stopped. The process should simply terminate when the call returns.
    auto success = ::StartServiceCtrlDispatcherW(st);
    if (0 == success) throw support::exception(TRACEMSG(
        "Error starting service, name: [" + name + "]," +
        " error: [" + sl::utils::errcode_to_string(::GetLastError()) + "]"));

    wilton::support::log_info(logger, "SCM service stopped");
    return support::make_null_buffer();
}

support::buffer misc_get_computer_name(sl::io::span<const char>) {
    auto wbuf = std::wstring();
    wbuf.resize(MAX_COMPUTERNAME_LENGTH + 1);
    DWORD len = wbuf.length();
    auto success = ::GetComputerNameW(std::addressof(wbuf.front()), std::addressof(len));
    if (0 == success) throw support::exception(TRACEMSG(
        "Error getting computer name," +
        " error: [" + sl::utils::errcode_to_string(::GetLastError()) + "]"));
    wbuf.resize(len);
    auto res = sl::utils::narrow(wbuf);
    return support::make_string_buffer(res);
}

support::buffer misc_show_message_box(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rcaption = std::ref(sl::utils::empty_string());
    auto rtext = std::ref(sl::utils::empty_string());
    auto ricon = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("caption" == name) {
            rcaption = fi.as_string_nonempty_or_throw(name);
        } else if ("text" == name) {
            rtext = fi.as_string_nonempty_or_throw(name);
        } else if ("icon" == name) {
            ricon = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rcaption.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'caption' not specified"));
    const std::string& caption = rcaption.get();
    if (rtext.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'text' not specified"));
    const std::string& text = rtext.get();
    if (ricon.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'icon' not specified"));
    const std::string& icon = ricon.get();

    // call winapi
    UINT uicon = 0;
    if ("info" == icon) {
        uicon = MB_ICONINFORMATION;
    } else if ("warning" == icon) {
        uicon = MB_ICONWARNING;
    } else if ("error" == icon) {
        uicon = MB_ICONERROR;
    } else {
        throw support::exception(TRACEMSG(
                "Invalid unsupported icon specified, value: [" + icon + "]," +
                " supported icons: [info, warning, error]"));
    }
    auto wcaption = sl::utils::widen(caption);
    auto wtext = sl::utils::widen(text);
    auto success = ::MessageBoxExW(
            nullptr, // hWnd
            wtext.c_str(), // lpText
            wcaption.c_str(), // lpCaption
            MB_OK | uicon, // uType
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)); // wLanguageId
    if (0 == success) throw support::exception(TRACEMSG(
        "Error showing message box," +
        " error: [" + sl::utils::errcode_to_string(::GetLastError()) + "]"));
    return support::make_null_buffer();
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        wilton::support::register_wiltoncall("winscm_start_service_control_dispatcher", wilton::winscm::start_service_control_dispatcher);
        wilton::support::register_wiltoncall("winscm_misc_get_computer_name", wilton::winscm::misc_get_computer_name);
        wilton::support::register_wiltoncall("winscm_misc_show_message_box", wilton::winscm::misc_show_message_box);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }

}
