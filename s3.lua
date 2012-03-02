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
--    -- Get bucket contents
--    --
--    local status = bucket:list("/", "path/", 100)
--    print("Found " .. #status.bucket.Contents .. " .. items in bucket")
--
--    -- Write some data to an S3 object, get it back, and delete the object
--    --
--    bucket:put("path/object.txt", "this is the object contents")
--    status = bucket:get("path/object.txt")
--    if not status.isError and status.response.code = 200 then
--        print("Got bucket object contents: " .. status.response.body)
--    end    
--    bucket:delete("path/object.txt")
--
--    -- Write a file to an S3 object and get a copy back
--    --
--    bucket:put_file("path/object.png", system.pathForFile("boulder.png", system.DocumentsDirectory))
--    bucket:get_file("path/object.png", system.pathForFile("new_boulder.png", system.DocumentsDirectory))
--
--
-- Notice: 
--
--    This module currently uses the LuaSocket networking interfaces.  These are
--    very well-designed and robust interfaces, but unfortunately they are all 
--    synchronous/blocking calls.  Some Lua environments provide multitasking (via
--    LuaLanes and other methods), and in those environments the LuaSocket interfaces
--    are a perfectly reasonable solution.  Unfortunately, Corona does not provide
--    any multitasking support, and all application code is executed on the main user
--    interface thread (meaning that your application will be non-responsive during
--    network I/O).
--
--    In order to support asynchronouse/cancellable network I/O, this module uses a 
--    technique designed by Diego Nehab (the creator of LuaSocket) and implemented
--    in the Lua module "dispatch".  It essentially blocks for 100ms at a time and
--    yeilds back to the main event thread.  You may notice some slight jerkiness if
--    there is a lot of UI activity happening during your network I/O, but in most 
--    cases this approach seems to work fine.  I'd like to thank Le Viet Bach of 
--    Rubycell .JSC for his original implementation of an http request using the 
--    dispatch method (in his "asyncHttp" module, a version of which is used here
--    as "async_http").
--
--    It would be preferrable to use the Corona asynchronous I/O support, as it is
--    truly asynchronous and supports https, but it is currently unusable for talking
--    to REST APIs like S3 (no support for the required verbs such as HEAD, PUT, and
--    DELETE, and no access to the HTTP response code, status, or headers, all of
--    which are needed to interact with a REST service in a meaningful way).  I have
--    entered a feature request to have this functionality added to the Corona async
--    network.request method.  I originally attempted to at least support bucket
--    list/get using the async network.request with GET, but found it to be buggy (it
--    was non-functional on Windows, and produced corrupt files on Android).  I submitted
--    a bug report regarding these bahviors.  If the Corona asynchronous I/O support
--    is ever improved to support the required functionality, and it is stable on all
--    platforms, then I will update the asynchronous request logic here to use it.
--
-- Testing Notes:
--
--    The unit tests below have been trimmed down substantially and will not work in
--    your local environment without modification.  Since Amazon doesn't have any
--    kind of test account or test fixture for S3, you will have to test against your
--    own S3 bucket/account (and modify the tests accordingly).  
--
--    For the sake of optimization, you will probably want to comment out the entire test
--    block at the end of this module when your testing is complete.
--
--====================================================================--
--
local M = {}

local asynch_http = require("async_http")

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

-- These should be set outside of this module, by the user of the module
M.AWS_Access_Key_ID = "--UNDEFINED--"
M.AWS_Secret_Key    = "--UNDEFINED--"

local function sha1_hmac( key, text )
    -- Corona doesn't support SHA1 (or any other algorithms) on Windows.  We have to go to a
    -- pure Lua implementation of sha1_hmac on Windows so we can test/dev in the simulator.
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
                header_lines[#header_lines + 1] = header:lower() .. ':' .. headers[header]
            end
            return table.concat(header_lines, "\n") .. "\n"
        end
    end
    
    local canonicalizedResourceString = "/" .. bucketName .. "/"
    if objectName then
        canonicalizedResourceString = canonicalizedResourceString .. objectName
    end
    
    local canonicalizedHeaderString = 
        method .. "\n"
        .. (headers["Content-MD5"] or "") .. "\n"
        .. (headers["Content-Type"] or "") .. "\n"
        .. (headers["Date"] or "") .. "\n"
        .. get_canonical_amz_headers(headers)
        .. canonicalizedResourceString
        
    --print("Canonicalized header string: " .. canonicalizedHeaderString)
        
    headers["Authorization"] = "AWS " .. M.AWS_Access_Key_ID .. ":" .. mime.b64(sha1_hmac(M.AWS_Secret_Key, canonicalizedHeaderString))

end

local function getHeaders(user_headers, content)
    local headers = {}
    headers["Date"] = os.date("!%a, %d %b %Y %H:%M:%S GMT")
    
    if content then
        headers["Content-Length"] = content:len()
        headers["Content-MD5"] = mime.b64(crypto.digest(crypto.md5, content, true))
    end
    
    -- Add caller-supplied headers (if any)
    if user_headers then
        for header, value in pairs(user_headers) do
            headers[header] = value
        end
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

local function loadFile(filepath, directory)
    local filepath = filepath
    if directory then
        filepath = system.pathForFile(filepath, directory)
    end
	local file, err = io.open(filepath, "rb")
	if file then
		local data = file:read("*a")
		io.close(file)
	    return data
	else
		print("Load error on open: ", err)
	end
end

local function saveFile(data, filepath, directory)
    local filepath = filepath
    if directory then
        filepath = system.pathForFile(filepath, directory)
    end
	local file, err = io.open(filepath, "wb")
    if file then
        file:write(data)
        io.close(file)
        return true
    else
        print("Save error on open: ", err)
    end
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
        
        if httpResponse then
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

-- We export this so that S3 callers can get the host name for checking connection
-- status, etc.
--
function M.getHostNameFromBucketName( bucketName )
    return bucketName .. ".s3.amazonaws.com"
end

--------------------------------------------------------------------------------
--
-- The S3 bucket object
--
--    bucket = s3.getBucket("bucketName")
--
--    bucket:list()   - "GET Bucket" (List objects) 
--    bucket:head()   - "HEAD Object"
--    bucket:get()    - "GET Object"
--    bucket:put()    - "PUT Object"
--    bucket:delete() - "DELETE Object"
--
--    All methods produce a status, as follows:
--
--      status
--        isError - true or false
--        errorMessage - error message, if isError is true
--        request - the http request constructed for the call
--          url - the url
--          method - the method, such as GET or POST
--          headers - the http request headers
--          body - the http request body (if any)
--        response - if isError is false, the http response
--          code - response code, such as 200 for success
--          status - resonse status string, such as "OK" or "Not Found"
--          headers - response headers
--          body - response body (if any)
--
--    All methods can be called synchronously or asynchronously, as follows:
--
--     * If no onComplete callback is provided, then the method blocks while
--       completing the request and returns the status to the caller.
--
--     * If an onComplete callback is provided, then the method will perform the
--       request asynchronously, returning a cancellable thread reference.  When the
--       request is completed, the onComplete callback will be called with the status.
--
--       An asynchronous request can be cancelled as follow:
--
--         local http_thread = bucket:get("boulder.png", nil, onComplete)
--         http_thread:cancel()
--
--------------------------------------------------------------------------------
--
function M.getBucket( bucketName )

    local s3_bucket = {
        bucketName = bucketName,
        host = M.getHostNameFromBucketName(bucketName),
    }
    
    ----------------------------------------------------------------------------
    -- Method: s3_bucket:list( delimiter, prefix, max_keys, marker, onComplete )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html
    --
    -- Example:
    --
    --    local status = bucket:list("/", "users/", 100)
    --
    -- When called on a bucket with the following contents:
    --
    --    /users/
    --    /users/bob/
    --    /users/matt/
    --    /users/episodes.json
    --
    -- Produces this status:
    --
    --    status.isError = false
    --    status.bucket.xmlns = http://s3.amazonaws.com/doc/2006-03-01/
    --    status.bucket.Name = BucketName
    --    status.bucket.MaxKeys = 100
    --    status.bucket.Prefix = users/
    --    status.bucket.Delimiter = /
    --    status.bucket.Contents[1].LastModified = 2012-02-22T06:53:49.000Z
    --    status.bucket.Contents[1].Key = users/
    --    status.bucket.Contents[1].StorageClass = STANDARD
    --    status.bucket.Contents[1].ETag = "xxxxxxxxxxxxxxxxxxxxxxxx"
    --    status.bucket.Contents[1].Owner.ID = xxxxxxxxxxxxxxxxxxxxxxxx
    --    status.bucket.Contents[1].Owner.DisplayName = xxxxxx
    --    status.bucket.Contents[1].Size = 0
    --    status.bucket.Contents[2].LastModified = 2012-02-22T06:55:12.000Z
    --    status.bucket.Contents[2].Key = users/episodes.json
    --    status.bucket.Contents[2].StorageClass = STANDARD
    --    status.bucket.Contents[2].ETag = "xxxxxxxxxxxxxxxxxxxxxxxx"
    --    status.bucket.Contents[2].Owner.ID = xxxxxxxxxxxxxxxxxxxxxxxx
    --    status.bucket.Contents[2].Owner.DisplayName = xxxxxx
    --    status.bucket.Contents[2].Size = 114
    --    status.bucket.CommonPrefixes[1].Prefix = users/bob/
    --    status.bucket.CommonPrefixes[2].Prefix = users/matt/
    --    status.bucket.Marker =
    --    status.bucket.IsTruncated = false  
    --    
    ----------------------------------------------------------------------------
    --
    function s3_bucket:list( delimiter, prefix, max_keys, marker, onComplete )

        -- Build the request    
        local httpRequest = {
            method = "GET",
            url = "http://" .. self.host .. "/",
            headers = getHeaders(),
            proxy = PROXY,
        }
        addAuthorizationHeader(httpRequest.method, self.bucketName, nil, httpRequest.headers)

        -- Create request querystring from parameters
        local listParams = {}
        listParams["delimiter"] = delimiter
        listParams["prefix"]    = prefix
        listParams["max-keys"]  = max_keys
        listParams["marker"]    = marker
        httpRequest.url = appendQueryString(httpRequest.url, listParams)

        local function createResultStatus( status )
            if status.isError then
                dbg("FAIL - bucket:list() request failed, reason: " .. status.errorMessage)
                dumpHttpRequestResponse(status.request)
            else
                dumpHttpRequestResponse(status.request, status.response)

                -- Convert the XML response body to a properly formed table
                local xmlParser = xml.newParser()
                local xmlResponse = xmlParser:ParseXmlText(status.response.body)
                local bucketList = simplify_xml(xmlResponse)
                
                -- Make sure .Contents is always a collection (even if it only has one entry)
                if bucketList.Contents and bucketList.Contents.Key then
                    bucketList.Contents = { bucketList.Contents }
                end
                
                -- Make sure .CommonPrefixes is always a collection (even if it has only one entry)
                if bucketList.CommonPrefixes and bucketList.CommonPrefixes.Prefix  then
                    bucketList.CommontPrefixes = { bucketList.CommonPrefixes }
                end

                status.bucket = bucketList
            end
            
            return status
        end
        
        if onComplete then
            local function onRequestComplete( status )
                onComplete(createResultStatus(status))
            end
            return asynch_http.request(httpRequest, onRequestComplete)
        else
            local status = asynch_http.request(httpRequest)
            return createResultStatus(status)
        end
        
    end
    
    -- Internal helper method for object calls
    --
    local function bucket_object_request( bucket, method, objectName, headers, objectData, responseFilePath, onComplete )

        local httpRequest = {
            method = method,
            url = "http://" .. bucket.host .. "/" .. objectName,
            headers = getHeaders(headers, objectData),
            body = objectData,
            proxy = PROXY,            
        }
        addAuthorizationHeader(httpRequest.method, bucket.bucketName, objectName, httpRequest.headers)

        local responseFilePath = responseFilePath
        
        local function createResultStatus( status )
            if status.isError then
                dbg("FAIL - bucket request failed, reason: " .. status.errorMessage)
                dumpHttpRequestResponse(status.request)
            else
                if status.response.code == 200 and status.response.body and responseFilePath then
                    -- We only want to save the body if it's a valid body response
                    saveFile(status.response.body, responseFilePath)
                    status.response.bodyFilePath = responseFilePath
                end
                dumpHttpRequestResponse(status.request, status.response)
            end
            
            return status
        end
        
        if onComplete then
            local function onRequestComplete( status )
                onComplete(createResultStatus(status))
            end
            return asynch_http.request(httpRequest, onRequestComplete)
        else
            local status = asynch_http.request(httpRequest)
            return createResultStatus(status)
        end
    end

    ----------------------------------------------------------------------------
    -- Method: s3_bucket:head( objectName, requestHeaders, onComplete )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectHEAD.html
    --
    ----------------------------------------------------------------------------
    --
    function s3_bucket:head( objectName, requestHeaders, onComplete )
        return bucket_object_request(self, "HEAD", objectName, requestHeaders, nil, nil, onComplete)
    end
        
    ----------------------------------------------------------------------------
    -- Method: s3_bucket:get( objectName, requestHeaders, onComplete )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGET.html
    --
    ----------------------------------------------------------------------------
    --
    function s3_bucket:get( objectName, requestHeaders, onComplete )
        return bucket_object_request(self, "GET", objectName, requestHeaders, nil, nil, onComplete)
    end

    function s3_bucket:get_file( objectName, filePath, requestHeaders, onComplete )
        return bucket_object_request(self, "GET", objectName, requestHeaders, nil, filePath, onComplete)
    end

    ----------------------------------------------------------------------------
    -- Method: s3_bucket:put( objectName, requestHeaders, data, onComplete )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPUT.html
    --
    ----------------------------------------------------------------------------
    --
    function s3_bucket:put( objectName, data, requestHeaders, onComplete )
        return bucket_object_request(self, "PUT", objectName, requestHeaders, data, nil, onComplete)
    end

    function s3_bucket:put_file( objectName, filePath, requestHeaders, onComplete )
        -- No point in streaming this since we have to get content length and compute the MD5
        -- digest anyway (and crypto.digest only takes a string).  So we just load the file
        -- here...
        --
        local data = loadFile(filePath)
        return self:put( objectName, data, requestHeaders, onComplete )
    end

    ----------------------------------------------------------------------------
    -- Method: s3_bucket:delete( objectName )
    --
    -- See: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectDELETE.html
    --
    ----------------------------------------------------------------------------
    --
    function s3_bucket:delete( objectName, onComplete )
        return bucket_object_request(self, "DELETE", objectName, nil, nil, nil, onComplete)
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
    local status = bucket:list("/", "users/", 100)
    if status.isError then
        print("TEST - bucket:get failed with error: " .. status.errorMessage)
    else
        if #status.bucket.Contents >= 2 then
            if status.bucket.Contents[2].Key == "users/episodes.json" then
                print("TEST - bucket:get passed, found entry")
            else
                print("TEST - bucket:get failed, entry not found")
            end
        else
            print("TEST - bucket:get failed, not enough entries, entry count: " .. #status.bucket.Contents)
        end
    end
end

function M.testListAsync(bucket)
    local function onComplete( status )
        if status.isError then
            print("TEST - async bucket:list failed with error: " .. status.errorMessage)
        else
            if #status.bucket.Contents >= 2 then
                if status.bucket.Contents[2].Key == "users/episodes.json" then
                    print("TEST - async bucket:list passed, found entry")
                else
                    print("TEST - async bucket:list failed, entry not found")
                end
            else
                print("TEST - async bucket:list failed, not enough entries, entry count: " .. #status.bucket.Contents)
            end
        end
    end
    print("Test - async bucket:list starting")
    bucket:list("/", "users/", 100, nil, onComplete)
end

function M.testHead(bucket)
    local status = bucket:head("boulder.png")
    if status.isError then
        print("TEST - bucket:head failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            if status.response.headers["content-type"] == "image/png" then
                print("TEST - bucket:head passed, correct content/type, data length: " .. status.response.body:len())
            else
                print("TEST - bucket:head failed, incorrect content type, was: " .. status.response.headers["content-type"])
            end
        else
            print("TEST - bucket:head failed, response code: " .. status.response.code)
        end        
    end
end

function M.testCustomHeaders(bucket)
    local headers = { }
    
    -- First we do a non-matching eTag (specified in a custom request header)
    --
    headers["If-Match"] = "non-matching-etag"
    local status = bucket:head("boulder.png", headers)
    if status.isError then
        print("TEST - bucket:head with custom headers failed with error: " .. status.errorMessage)
    else
        if status.response.code == 412 then -- "412 Precondition Failed" is the expected result
            print("TEST - bucket:head with custom headers passed for 'Not Found' case")
        else
            print("TEST - bucket:head failed, response code: " .. status.response.code)
        end        
    end
    
    -- Then we do a matching eTag (specified in a custom request header)
    --
    headers["If-Match"] = "ea9035ce951323d8c66a3c4dabda9e64"
    status = bucket:head("boulder.png", headers)
    if status.isError then
        print("TEST - bucket:head with custom headers failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            print("TEST - bucket:head with custom headers passed for 'Found' case")
        else
            print("TEST - bucket:head failed, response code: " .. status.response.code)
        end        
    end

end

function M.testGet(bucket)
    local status = bucket:get("boulder.png")
    if status.isError then
        print("TEST - bucket:get failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            print("TEST - bucket:get passed, data length: " .. status.response.body:len())
        else
            print("TEST - bucket:get failed, response code: " .. status.response.code)
        end        
    end
end

function M.testGetFile(bucket)
    local filePath = system.pathForFile("dwn_boulder.png", system.DocumentsDirectory)
    local status = bucket:get_file("boulder.png", filePath)
    if status.isError then
        print("TEST - bucket:get_file failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            if status.response.bodyFilePath == filePath then
                print("TEST - bucket:get_file passed, data length: " .. status.response.body:len())
            else
                print("TEST - bucket:get_file failed, incorrect bodyFilePath: ", status.response.bodyFilePath)
            end
        else
            print("TEST - bucket:get_file failed, response code: " .. status.response.code)
        end        
    end
end

function M.testGetAsync(bucket)
    local function onComplete( status )
        if status.isError then
            print("TEST - async bucket:get failed with error: " .. status.errorMessage)
        else
            if status.response.code == 200 then
                print("TEST - async bucket:get passed, data length: " .. status.response.body:len())
            else
                print("TEST - async bucket:get failed, response code: " .. status.response.code)
            end        
        end
    end
    print("Test - async bucket:get starting")
    bucket:get("boulder.png", nil, onComplete)
end

function M.testCancelGetAsync(bucket)
    local function onComplete( status )
        print("TEST - cancel async bucket:get failed, callback should not have been reached")
    end
    print("Test - cancel async bucket:get starting")
    local http_thread = bucket:get("boulder.png", nil, onComplete)
    http_thread:cancel()
    print("Test - cancel async bucket:get ending")
end

function M.testPut(bucket)
    local status = bucket:put("test.txt", "This is a test of S3 put", nil)
    if status.isError then
        print("TEST - bucket:put failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            print("TEST - bucket:put passed")
        else
            print("TEST - bucket:put failed, response code: " .. status.response.code)
        end        
    end
end

function M.testPutFile( bucket )
    local status = bucket:put_file("cover.jpg", system.pathForFile("init_cover.jpeg", system.DocumentsDirectory))
    if status.isError then
        print("TEST - bucket:put failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            print("TEST - bucket:put passed")
        else
            print("TEST - bucket:put failed, response code: " .. status.response.code)
        end        
    end
end

function M.testPutAsync(bucket)
    local function onComplete( status )
        if status.isError then
            print("TEST - async bucket:put failed with error: " .. status.errorMessage)
        else
            if status.response.code == 200 then
                print("TEST - async bucket:put passed")
            else
                print("TEST - async bucket:put failed, response code: " .. status.response.code)
            end        
        end
    end
    print("Test - async bucket:put starting")
    bucket:put("test.txt", "This is a test of S3 put", nil, onComplete)
end

function M.testDelete(bucket)
    local status = bucket:delete("test.txt")
    if status.isError then
        print("TEST - bucket:delete failed with error: " .. status.errorMessage)
    else
        if status.response.code == 204 then
            -- Note - for DELETE a "204 No Content" is actually a success
            print("TEST - bucket:delete passed")
        else
            print("TEST - bucket:delete failed, response code: " .. status.response.code)
        end        
    end
end

function M.testMetaData(bucket)
    local headers = {}
    headers["x-amz-meta-user-data"] = "This is user metadata"
    local status = bucket:put("test.txt", "This is a test of S3 put", headers)
    if status.isError then
        print("TEST - metadata - bucket:put failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            print("TEST - metadata - bucket:put passed")
        else
            print("TEST - metadata- bucket:put failed, response code: " .. status.response.code)
        end        
    end
    
    status = bucket:head("test.txt")
    if status.isError then
        print("TEST - metadata- bucket:head with custom headers failed with error: " .. status.errorMessage)
    else
        if status.response.code == 200 then
            if status.response.headers["x-amz-meta-user-data"] == "This is user metadata" then
                print("TEST - metadata - PASSED, metadata response header found")
            else
                print("TEST - metadata - FAILED, metadata response header NOT found")
            end
        else
            print("TEST - metadata - bucket:head failed, response code: " .. status.response.code)
        end        
    end
    
    status = bucket:list("/", "", 100)
end

function M.testAll()
    
    local bucket_name = "smasher"
    local bucket = M.getBucket(bucket_name)
    
    M.testAuthComputation()
    M.testSha1Module()
    
    M.testList(bucket)
    M.testHead(bucket)
    M.testGet(bucket)
    M.testGetFile(bucket)
    M.testPut(bucket)
    M.testPutFile(bucket)
    M.testDelete(bucket)

    M.testCustomHeaders(bucket)
    M.testMetaData(bucket)

    M.testListAsync(bucket)
    M.testGetAsync(bucket)
    M.testPutAsync(bucket)
    
    M.testCancelGetAsync(bucket)
end

return M
