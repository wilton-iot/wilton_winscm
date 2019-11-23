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

#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/registrar.hpp"

namespace wilton {
namespace systemd {

namespace { //anonymous

const std::string logger = std::string("wilton.winscm");

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

    // call
    wilton::support::log_debug(logger, std::string("Is due to call SCM,") +
            " message: [" + state + "]");
    // todo
    wilton::support::log_debug(logger, "Service stopped by SCM");
    return support::make_null_buffer();
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        wilton::support::register_wiltoncall("winscm_start_service_control_dispatcher", wilton::winscm::start_service_control_dispatcher);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }

}
