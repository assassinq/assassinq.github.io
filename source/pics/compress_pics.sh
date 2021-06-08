#!/bin/bash
#https://www.jianshu.com/p/05bdcbe320f6

for img in `find -E ./ -iregex ".*\.(jpg|jpeg)"` ; do
    jpegoptim --strip-exif --max=95 $img
done

for img in `find -E ./ -iregex ".*\.png"` ; do
    optipng $img
done

