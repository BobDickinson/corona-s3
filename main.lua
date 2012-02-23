-- 
-- Abstract: S3 Demo
--
-- Version: 1.0
-- 
-- Copyright (C) 2012 Triple Dog Dare Games. All Rights Reserved.

local s3 = require("s3")

local function s3_test( )

    s3.isDebug = true

    --s3.AWS_Access_Key_ID = "_YOUR_ACCESS_KEY_GOES_HERE_"
    --s3.AWS_Secret_Key    = "_YOUR_SECRET_KEY_GOES_HERE_"

    s3.testAll()
    
end

s3_test()
