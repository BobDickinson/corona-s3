--====================================================================--
-- Module: s3   
-- 
--    Copyright (C) 2012 Triple Dog Dare Games, Inc.  All Rights Reserved.
--
-- License:
--
--    Permission is hereby granted, free of charge, to any person obtaining a copy of 
--    this software and associated documentation files (the "Software"), to deal in the 
--    Software without restriction, including without limitation the rights to use, copy, 
--    modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
--    and to permit persons to whom the Software is furnished to do so, subject to the 
--    following conditions:
-- 
--    The above copyright notice and this permission notice shall be included in all copies 
--    or substantial portions of the Software.
-- 
--    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
--    INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
--    PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
--    FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
--    OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
--    DEALINGS IN THE SOFTWARE.
--
-- Overview: 
--
--    This module supports access to the Amazon Simple Storage Service (S3), a
--    popular cloud-based storage platform, from Corona SDK applications.
--
--    For more information, see:
--
--        http://aws.amazon.com/s3/
--        http://www.anscamobile.com/corona/
--
-- WARNING: 
--
--    FOR TEST ONLY - DO NOT USE IN RELEASED APPLICATIONS!
--
--    This module currently uses the Lua Sockets networking interfaces.  These are
--    very well-designed and robust interfaces, but unfortunately they are all 
--    synchronous/blocking calls.  Some Lua environments provide multitasking (via
--    LuaLanes and other methods), and in those environments the Lua Sockets interfaces
--    are a perfectly reasonable solution.  Unfortunately, Corona does not provide
--    any multitasking support, and all application code is executed on the main user
--    interface thread.  This means that your app will be completely non-responsive
--    for the duration of any network call.  Since Corona apps often run on mobile devices
--    with slow or unreliable data connections, this means that your app can hang for a
--    very long time (up to the platform-specific timeout, typically 30 seconds to a minute
--    for a complete failure, but it could be significantly longer if the I/O doesn't 
--    fail, but just takes a really long time to complete).
--
--    It is not a good idea to use the code below (or really, any code that uses the blocking
--    I/O) in a production application, given that no decent app should ever be non-responsive
--    for any significant period of time (even a download of a smallish file over a fast WIFI
--    connection can take 5-10 seconds, and that's if everything goes well).
--
--    I am using this code for testing currently.  I have found the asynchronous I/O support 
--    in Corona to be unusable for talking to REST APIs like S3 (they don't support the
--    required verbs such as HEAD, PUT, and DELETE, and they don't provide access to the
--    HTTP response code, status, or headers, all of which are needed to interact with a 
--    REST service in a meaningful way).  I have entered a feature request to have this 
--    functionality added to the Corona async network.request method, and my hope is that
--    they will be added soon so that I can update this module and deploy S3 support in my
--    released application.  I originally attempted to at least support bucket list/get using 
--    the async network.request with GET, but found it to be buggy (it was non-functional
--    on Windows, and produced corrupt files on Android).  I submitted a bug report regarding
--    these bahviors.
--
-- To Do:
--
--    Add bucket:head( ) support (determine object existence, get metadata)
--
--    Add support for getting response headers (and associated metadata) on bucket:get( )
--
--    Add bucket:delete( ) to delete object in bucket
--
--    Implement asynchronous network I/O when/if functionality provided in Corona
--
-- Testing Notes:
--
--    The unit tests below have been trimmed down substantially.  Since Amazon doesn't have
--    any kind of test account or test fixture for S3, you will have to test against your own
--    S3 bucket/account.  The original local version of my tests uploaded and downloaded files
--    and compared against reference files in order to validate.  They also validated the bucket
--    contents on list().  
--
--    For the sake of optimization, you will probably want to comment out the entire test block
--    at the end of this module when your testing is complete.
--
-- Usage:
--
--    local s3 = require("s3")
--
--    -- Set credentials
--    s3.AWS_Access_Key_ID = "your_access_key"
--    s3.AWS_Secret_Key    = "your_secret_key"
--
--    -- Get a bucket object
--    local bucket = s3.getBucket("bucketName")
--
--    -- List bucket contents, Get and Put files
--    --
--    local bucket_contents = bucket:list("/", "path/", 100)
--    local object_data = bucket:get("path/object.txt")
--    bucket:put("path/object.txt", "this is the object contents")
--
--====================================================================--
local M = {}

local crypto = require("crypto")
local mime = require("mime")
local http = require("socket.http")
local url = require("socket.url")
local ltn12 = require("ltn12")

local xml = require("xml")
local sha1 = require("sha1") -- Pure Lua - Used for Windows sim only

-- If you have a functioning debug proxy, you can set it below and it will be used by all
-- network requests in this module.
--
local PROXY -- = "http://127.0.0.1:8888"

-- These should be set outside of this module, but the user of the module
M.AWS_Access_Key_ID = "--UNDEFINED--"
M.AWS_Secret_Key    = "--UNDEFINED--"

local function sha1_hmac( key, text )
    -- Corona doesn't support SHA1 (or any other algorithms) on Windows.  We have to go to a
    -- pure Lua implementation of sha1_hmac on Windows so we can test/dev in the simulator.
    -- Not sure if this is needed on Mac also.
    --
    if system.getInfo("platformName") == "Win" then
        return (sha1.hmac_sha1_binary(key, text))
    else
        return crypto.hmac(crypto.sha1, text, key, true)
    end
end

-- Compute and add the Amazon S3 REST authorization header, as specified here:
--
--   http://docs.amazonwebservices.com/AmazonS3/latest/dev/RESTAuthentication.html
--
local function addAuthorizationHeader( method, bucketName, objectName, headers )

    local function get_canonical_amz_headers( headers )
        local amz_headers = {}
        for header, value in pairs(headers) do
            if header:match('^x%-amz%-') then
                table.insert(amz_headers, header)
            end
        end
        if #amz_headers == 0 then
            return "" 
        else
            table.sort(amz_headers)
            local header_lines = {}
            for i = 1, #amz_headers do
                local header = amz_headers[i]
                header_lines[#header_lines + 1] = header:lower() .. ':' .. headers[header]:lower()
            end
            return table.concat(header_lines, "\n") .. "\n"
        end
    end
    
    local canonicalizedResourceString = "/" .. bucketName:lower() .. "/"
    if objectName then
        canonicalizedResourceString = canonicalizedResourceString .. objectName:lower()
    end
    
    local canonicalizedHeaderString = 
        method .. "\n"
        .. (headers["Content-MD5"] or "") .. "\n"
        .. (headers["Content-Type"] or "") .. "\n"
        .. (headers["Date"] or "") .. "\n"
        .. get_canonical_amz_headers(headers)
        .. canonicalizedResourceString
        
    headers["Authorization"] = "AWS " .. M.AWS_Access_Key_ID .. ":" .. mime.b64(sha1_hmac(M.AWS_Secret_Key, canonicalizedHeaderString))

end

local function getHeaders(content)
    local headers = {}
    headers["Date"] = os.date("!%a, %d %b %Y %H:%M:%S GMT")
    
    if content then
        headers["Content-Length"] = content:len()
        headers["Content-MD5"] = mime.b64(crypto.digest(crypto.md5, content, true))
    end

    return headers
end

local function createQueryString( params )
    local queryString
    for k, v in pairs(params) do
        if queryString then
            queryString = queryString .. "&"
        else
            queryString = "?"            
        end
        queryString = queryString .. k .. "=" .. url.escape(v)
    end
    return queryString
end

local function appendQueryString( url, params )
    local url = url
    local queryString = createQueryString(params)
    if queryString then
        url = url .. queryString
    end
    return url
end

-------------------------------------------------------------------------------
-- Debug logging support
--

M.isDebug = true

local function dbg( ... )
    if M.isDebug then
        print(unpack(arg))
    end
end

local function dbgf( ... )
    if M.isDebug then
        print(string.format(unpack(arg)))
    end
end

local function dumpHttpRequestResponse( httpRequest, httpResponse )
    if M.isDebug then
        -- Dump request
        dbgf("HTTP request: %s %s", httpRequest.method, httpRequest.url)
        for header, value in pairs(httpRequest.headers) do
            dbgf("HTTP request header - %s: %s", header, value)
        end
        
        -- Dump response
        if type(httpResponse.code) == "string" then
            -- Certain failures that don't produce an HTTP response at all (like "connection refused")
            -- result in an error string in the response.code.
            dbgf("HTTP response: %s", httpResponse.code)
        else
            dbgf("HTTP response: %i %s", httpResponse.code, httpResponse.status)
        end
        for header, value in pairs(httpResponse.headers) do
            dbgf("HTTP response header - %s: %s", header, value)
        end
        
        local ct = httpResponse.headers["content-type"]
        if httpResponse.body and (ct == "application/xml" or ct == "text/plain") then
            dbg("HTTP response body:" .. httpResponse.body)
        end
    end
end

-------------------------------------------------------------------------------
-- XML to Table simplification.  Modified version of original function found
-- here:
--
--    http://developer.anscamobile.com/code/much-improved-dump-function-and-xml-simplify
--
-------------------------------------------------------------------------------
--
local function simplify_xml( xml, tbl, indent )
    if (indent == nil) then indent = ''; else indent = indent .. '   '; end
    if (tbl == nil) then tbl = {}; end

    dbg(indent .. xml.name)
    for k, v in pairs(xml.properties) do
        dbg(indent .. '   .' .. k .. ' = ' .. v)
        tbl[k] = v
    end

    if (xml.value ~= nil) then
        dbg(indent .. '   "' .. xml.value .. '"')
        tbl.value = xml.value
    end

    if (#xml.child > 0) then dbg(indent..'{'); end
    for i=1, #xml.child do
        local name = xml.child[i].name
        local t = tbl[name]
        if (t == nil) then
            -- element name not seen yet
            tbl[name] = simplify_xml( xml.child[i], nil, indent )
        elseif (#t == 0) then
            -- second sighting of element name, convert into table
            dbg(indent .. '   ,')
            t = { t }
            tbl[name] = t
            t[2] = simplify_xml( xml.child[i], nil, indent )
        else
            -- numerous sighting of element name, add to table
            dbg(indent .. '   ,')
            t[#t+1] = simplify_xml( xml.child[i], nil, indent )
        end
    end
    if (#xml.child > 0) then dbg(indent..'}'); end
    
    function tablelength(T)
        local count = 0
        for _ in pairs(T) do count = count + 1 end
        return count
    end

    local tblAttrCnt = tablelength(tbl)
    if tblAttrCnt == 0 then
        -- If an entity has no attributes/values, make it a "false" value instead of an empty table
        tbl = false
    elseif tbl.value and tblAttrCnt == 1 then
        -- If an entity has only a value, then make that the value of the entity (instead of a .value attribute)               
        tbl = tbl.value
    end

    return tbl
end

--------------------------------------------------------------------------------
--
-- The S3 bucket object
--
--    bucket = s3.getBucket("bucketName")
--
--    bucket:list() - "GET Bucket" (List objects) 
--    bucket:get()  - "GET Object"
--    bucket:put()  - "PUT Object"
--
--------------------------------------------------------------------------------
--
function M.getBucket( bucketName )

    local s3_bucket = {
        bucketName = bucketName,
        host = bucketName .. ".s3.amazonaws.com"
    }
    
    ----------------------------------------------------------------------------
    -- Method: s3_bucket:list( delimiter, prefix, max_keys, marker )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html
    --
    -- Example:
    --
    --    local result = bucket:list("/", "users/", 100)
    --
    -- When called on a bucket with the following contents:
    --
    --    /users/
    --    /users/bob/
    --    /users/matt/
    --    /users/episodes.json
    --
    -- Produces this result:
    --
    --    result.xmlns = http://s3.amazonaws.com/doc/2006-03-01/
    --    result.Name = BucketName
    --    result.MaxKeys = 100
    --    result.Prefix = users/
    --    result.Delimiter = /
    --    result.Contents[1].LastModified = 2012-02-22T06:53:49.000Z
    --    result.Contents[1].Key = users/
    --    result.Contents[1].StorageClass = STANDARD
    --    result.Contents[1].ETag = "xxxxxxxxxxxxxxxxxxxxxxxx"
    --    result.Contents[1].Owner.ID = xxxxxxxxxxxxxxxxxxxxxxxx
    --    result.Contents[1].Owner.DisplayName = xxxxxx
    --    result.Contents[1].Size = 0
    --    result.Contents[2].LastModified = 2012-02-22T06:55:12.000Z
    --    result.Contents[2].Key = users/episodes.json
    --    result.Contents[2].StorageClass = STANDARD
    --    result.Contents[2].ETag = "xxxxxxxxxxxxxxxxxxxxxxxx"
    --    result.Contents[2].Owner.ID = xxxxxxxxxxxxxxxxxxxxxxxx
    --    result.Contents[2].Owner.DisplayName = xxxxxx
    --    result.Contents[2].Size = 114
    --    result.CommonPrefixes[1].Prefix = users/bob/
    --    result.CommonPrefixes[2].Prefix = users/matt/
    --    result.Marker =
    --    result.IsTruncated = false  
    --    
    ----------------------------------------------------------------------------
    --
    function s3_bucket:list( delimiter, prefix, max_keys, marker )

        -- Build the request    
        local httpRequest = {
            method = "GET",
            url = "http://" .. self.host .. "/",
            headers = getHeaders(),
        }
        addAuthorizationHeader(httpRequest.method, self.bucketName, nil, httpRequest.headers)

        -- Create request querystring from parameters
        local listParams = {}
        listParams["delimiter"] = delimiter
        listParams["prefix"]    = prefix
        listParams["max-keys"]  = max_keys
        listParams["marker"]    = marker
        httpRequest.url = appendQueryString(httpRequest.url, listParams)

        -- Create response table and process request
        
        local httpResponse = {
            body = {},
        }
        
        _, httpResponse.code, httpResponse.headers, httpResponse.status = http.request {	
            url = httpRequest.url,
            method = httpRequest.method,
            headers = httpRequest.headers,
            sink = ltn12.sink.table(httpResponse.body),
            proxy = PROXY,
        }
        httpResponse.body = table.concat(httpResponse.body)
        
        dumpHttpRequestResponse(httpRequest, httpResponse)

        -- Convert the XML response body to a properly formed table
        
        local xmlParser = xml.newParser()
        local xmlResponse = xmlParser:ParseXmlText(httpResponse.body)

        local result = simplify_xml(xmlResponse)
        
        -- Make sure .Contents is always a collection (event if it only has one entry)
        if result.Contents and result.Contents.Key then
            result.Contents = { result.Contents }
        end
        
        -- Make sure .CommonPrefixes is always a collection (even if it has only one entry)
        if result.CommonPrefixes and result.CommonPrefixes.Prefix  then
            result.CommontPrefixes = { result.CommonPrefixes }
        end
        
        result.response = httpResponse -- Provide the full response detail also
        return result
    end
    
    ----------------------------------------------------------------------------
    -- Method: s3_bucket:get( objectName )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGET.html
    --
    -- Returns: Object contents if GET successful, otherwise false
    --
    ----------------------------------------------------------------------------
    --
    function s3_bucket:get( objectName )
    
        local httpRequest = {
            method = "GET",
            url = "http://" .. self.host .. "/" .. objectName,
            headers = getHeaders(),
        }
        addAuthorizationHeader(httpRequest.method, self.bucketName, objectName, httpRequest.headers)

        local httpResponse = { 
            body = {},
        }
        
        _, httpResponse.code, httpResponse.headers, httpResponse.status = http.request {	
            url = httpRequest.url,
            method = httpRequest.method,
            headers = httpRequest.headers,
            sink = ltn12.sink.table(httpResponse.body),
            proxy = PROXY,
        }
        httpResponse.body = table.concat(httpResponse.body)
        
        dumpHttpRequestResponse(httpRequest, httpResponse)
        
        if httpResponse.code == 200 then
            return httpResponse.body
        else
            return false
        end
        
    end

    ----------------------------------------------------------------------------
    -- Method: s3_bucket:put( objectName, data )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPUT.html
    --
    -- Returns: true if PUT successul, otherwise false
    --
    ----------------------------------------------------------------------------
    --
    function s3_bucket:put( objectName, data )
    
        local httpRequest = {
            method = "PUT",
            url = "http://" .. self.host .. "/" .. objectName,
            headers = getHeaders(data),
            body = data,
        }
        addAuthorizationHeader(httpRequest.method, self.bucketName, objectName, httpRequest.headers)
        
        local httpResponse = { 
            body = {},
        }
        
        _, httpResponse.code, httpResponse.headers, httpResponse.status = http.request {	
            url = httpRequest.url,
            method = httpRequest.method,
            headers = httpRequest.headers,
            source = ltn12.source.string(httpRequest.body), 
            sink = ltn12.sink.table(httpResponse.body),
            proxy = PROXY,
        }
        httpResponse.body = table.concat(httpResponse.body)
        
        dumpHttpRequestResponse(httpRequest, httpResponse)
        
        return httpResponse.code == 200
        
    end

    return s3_bucket
end    

-- =============================================================================================
--
--  Unit tests
--
-- =============================================================================================


-- Verify the Amazon S3 authorization example from: 
--
--   http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html    
--
function M.testAuthComputation()

    local origAccessKey = M.AWS_Access_Key_ID
    local origSecretKey = M.AWS_Secret_Key
    
    M.AWS_Access_Key_ID = "44CF9590006BF252F707"
    M.AWS_Secret_Key = "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"

    local headers = {}
    headers["Date"] = "Thu, 17 Nov 2005 18:49:58 GMT"
    headers["Content-Type"] = "text/html"
    headers["Content-MD5"] = "c8fdb181845a4ca6b8fec737b3581d76"
    headers["x-amz-magic"] = "abracadabra"
    headers["x-amz-meta-author"] = "foo@bar.com"
    
    local bucket = "quotes"
    local object = "nelson"
    
    addAuthorizationHeader("PUT", bucket, object, headers)

    local expectedValue = "AWS 44CF9590006BF252F707:jZNOcbfWmD/A/f3hSvVzXZjM2HU="
    if headers["Authorization"] == expectedValue then
        print("TEST - Authorization test passed")
    else
        print("TEST - Authorization test failed, authorization was:", headers["Authorization"])
    end
    
    M.AWS_Access_Key_ID = origAccessKey 
    M.AWS_Secret_Key = origSecretKey

end

-- Verify that our pure Lua sha1 module passes the same test vector as above
--
function M.testSha1Module()

    local text = "PUT\nc8fdb181845a4ca6b8fec737b3581d76\ntext/html\nThu, 17 Nov 2005 18:49:58 GMT\nx-amz-magic:abracadabra\nx-amz-meta-author:foo@bar.com\n/quotes/nelson"
    local key = "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"

    local value = mime.b64((sha1.hmac_sha1_binary(key, text)))
    local expectedValue = "jZNOcbfWmD/A/f3hSvVzXZjM2HU="

    if value == expectedValue then
        print("TEST - sha1 hmac test passed")
    else
        print("TEST - sha1 hmac test failed, was:", value)
    end
end

function M.testList(bucket)
    local result = bucket:list("/", "users/", 100)
end

function M.testGet(bucket)
    local result = bucket:get("boulder.png")
    if result then
        print("TEST - bucket:get passed, data length: " .. result:len())
    else
        print("TEST - bucket:get failed")
    end
end

function M.testPut(bucket)
    local result = bucket:put("test.txt", "This is a test of S3 put")
    if result then
        print("TEST - bucket:put passed")
    else
        print("TEST - bucket:get failed")
    end
end

function M.testAll()
    
    local bucket_name = "smasher"
    local bucket = M.getBucket(bucket_name)
    
    M.testAuthComputation()
    M.testSha1Module()
    
    M.testList(bucket)
    
    M.testGet(bucket)
    M.testPut(bucket)

end

return M
