//
//  RFC2898DeriveBytes.h
//
//  Created by Matt Reagan on 6/25/17.
//  Copyright (c) 2017 Matt Reagan. All rights reserved.
//
//  Mimics the functionality of .NET's RFC2898DeriveBytes class.
//
//  Released under the MIT License:
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE.

#import <Foundation/Foundation.h>

@interface RFC2898DeriveBytes : NSObject

/** Uses RFC2898 to derive bytes from a password and random salt. Make sure that the length of deriveBytes is set prior to sending this message, as that determines how many bytes to derive from the password and the salt. */

+ (void)deriveBytes:(NSMutableData *)deriveBytes
       fromPassword:(NSString *)password
            andSalt:(NSData *)salt;

/** Derives a key an initialization vector suitable for AES128 encryption from a password and random salt. */

+ (void)deriveKey:(NSMutableData *)key
            andIV:(NSMutableData *)initialValue
     fromPassword:(NSString *)password
          andSalt:(NSData *)salt;

@end
