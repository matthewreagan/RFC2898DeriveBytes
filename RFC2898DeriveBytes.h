//
//  RFC2898DeriveBytes.h
//
//  Created by Matt Reagan on 6/25/17.
//  Copyright (c) 2017 Matt Reagan. All rights reserved.
//
//  Mimics the functionality of .NET's RFC2898DeriveBytes class.

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
