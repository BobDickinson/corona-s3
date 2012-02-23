--===========================================================================--
-- Module: async_http
--===========================================================================--
--
-- Solution originally found at:
--
--    http://developer.anscamobile.com/code/cross-platform-asynchronous-http-request
--
-- Header and license from original file are included below, per the license.
-- Note that this module has been modified significantly from the original
-- implementation.
--
--[[
	File:           asyncHttp.lua
	Purpose:        Asynchronous HTTP request for Corona SDK
	Author:         Le Viet Bach
	Company:		Rubycell .JSC
 
 
    Copyright (c) 2011 Le Viet Bach

    This software is provided 'as-is', without any express or implied
    warranty. In no event will the authors be held liable for any damages
    arising from the use of this software.

    Permission is granted to anyone to use this software for any purpose,
    including commercial applications, and to alter it and redistribute it
    freely, subject to the following restrictions:

       1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.

       2. Altered source versions must be plainly marked as such, and must not be
       misrepresented as being the original software.

       3. This notice may not be removed or altered from any source
       distribution.
]]--
-------------------------------------------------------------------------------
--
-- Note: Make sure to include (require) this module before any other modules that use
--       any Lua sockets functionality.
--
-- Usage:
--
--    async_http.request( httpRequest [,listener] )
--
--    Where httpRequest is a table containing the following
--      url - the url
--      method - the HTTP method, such as GET or POST
--      headers (optional) - request headers
--      body (optional) - request body
--      proxy (optional) - proxy to be used, in the form "http://hostAddress:hostPort"
--
--    This function produces an http request "status".
--  
--    If no listener is provided, then this function blocks while completing the request
--    and returns the status to the caller.
--
--    If a listener is provided, then this function will perform the request asynchronously,
--    returning a cancellable thread reference.  When the request is completed, the 
--    listener will be called with the status. 
--
--    status
--      isError - true or false
--      errorMessage - error message, if isError is true
--      request - the originally provided httpRequest
--      response - if isError is false, the http response table
--        code - response code, such as 200 for success
--        status - resonse status string, such as "OK" or "Not Found"
--        headers - response headers
--        body - response body (if any)
--     
-- Example:
--
--    local httpRequest = {
--        url = "http://www.google.com",
--        method = "GET",
--        headers = { Date =  os.date("!%a, %d %b %Y %H:%M:%S GMT") },
--    }
--
--    -- Blocking get
--    status = async_http.request(httpRequest)
--    if not status.isError and status.response.code == 200 then
--        print("Blocking get - page length was: ", status.response.body:len())
--    end
--
--    -- Asynchronous get
--    local function onGetComplete( status )
--        if not status.isError and status.response.code == 200 then
--            print("Asynchronous get - page length was: ", status.response.body:len())
--        end
--    end
--    http_thread = async_http.request(httpRequest, onGetComplete)
--
--    -- Call http_thread:cancel() to terminate before completion, if desired
--
------------------------------------------------------------------------
--

local M = {}

local socket = require "socket"
local dispatch = require "dispatch"
local http = require "socket.http"
local ltn12 = require "ltn12"
dispatch.TIMEOUT = 10
local Runtime = Runtime
local table = table
local print = print
local coroutine = coroutine

local function blockingRequest( httpRequest )

    local body
    if httpRequest.body then
        body = ltn12.source.string(httpRequest.body)
    end

    local httpResponse = { 
        body = {},
    }
    
    local result
    result, httpResponse.code, httpResponse.headers, httpResponse.status = http.request{
        url = httpRequest.url,
        method = httpRequest.method,
        headers = httpRequest.headers,
        source = body,
        sink = ltn12.sink.table(httpResponse.body),
        proxy = httpRequest.proxy,
    }
    if result then
        httpResponse.body = table.concat(httpResponse.body)
        return {
            isError = false,
            request = httpRequest,
            response = httpResponse,
        }
    else
        return {
            isError = true,
            errorMessage = httpResponse.code,
            request = httpRequest,
        }
    end

end

local function asyncRequest( httpRequest, listener )

	local handler = dispatch.newhandler("coroutine")
	local running = true
    
	handler:start(function()
    
		local body
        if httpRequest.body then
            body = ltn12.source.string(httpRequest.body)
        end

        local httpResponse = { 
            body = {},
        }
        
        local result
		result, httpResponse.code, httpResponse.headers, httpResponse.status = http.request{
			url = httpRequest.url,
			method = httpRequest.method,
			create = handler.tcp,
			headers = httpRequest.headers,
			source = body,
			sink = ltn12.sink.table(httpResponse.body),
            proxy = httpRequest.proxy,
		}
		if result then
            httpResponse.body = table.concat(httpResponse.body)
			listener{
				isError = false,
                request = httpRequest,
				response = httpResponse,
			}
		else
			listener{
				isError = true,
                errorMessage = httpResponse.code,
                request = httpRequest,
			}
		end
		running = false
        
	end)
    
	local httpThread = {}
    
	function httpThread.enterFrame()
		if running then
            handler:step()
		else
			Runtime:removeEventListener("enterFrame", httpThread)
		end
	end
    
	function httpThread:cancel()
		Runtime:removeEventListener("enterFrame", self)
		handler = nil
	end
    
	Runtime:addEventListener("enterFrame", httpThread)
	return httpThread
end

function M.request( httpRequest, listener )
    if listener then
        return asyncRequest(httpRequest, listener)
    else
        return blockingRequest(httpRequest)
    end
end

return M