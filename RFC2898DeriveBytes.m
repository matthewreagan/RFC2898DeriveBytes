//
//  RFC2898DeriveBytes.m
//
//  Created by Matt Reagan on 6/25/17.
//  Copyright (c) 2017 Matt Reagan. All rights reserved.
//

#import "RFC2898DeriveBytes.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>

@implementation RFC2898DeriveBytes

+ (void)deriveBytes:(NSMutableData *)deriveBytes
       fromPassword:(NSString *)password
            andSalt:(NSData *)salt
{
    const char * passPhraseBytes = [password UTF8String];
    int passPhraseLength = (int)strlen(passPhraseBytes);
    
    /*  Copy the salt into a mutable buffer. We need to append 4 bytes
        onto the end that we change through each iteration of the algorithm. */
    
    NSMutableData *mSalt = [NSMutableData dataWithData:salt];
    [mSalt increaseLengthBy:4];
    
    unsigned char mac[CC_SHA1_DIGEST_LENGTH];
    unsigned char outputBytes[CC_SHA1_DIGEST_LENGTH];
    unsigned char U[CC_SHA1_DIGEST_LENGTH];
    const int iterations = 1000;
    int i;
    int generatedBytes = 0;
    unsigned char blockCount = 0;
    
    while (generatedBytes < [deriveBytes length])
    {
        bzero(mac, CC_SHA1_DIGEST_LENGTH);
        bzero(outputBytes, CC_SHA1_DIGEST_LENGTH);
        bzero(U, CC_SHA1_DIGEST_LENGTH);
        
        blockCount++;
        unsigned char *mSaltBytes = (unsigned char *)[mSalt mutableBytes];
        mSaltBytes[[mSalt length] - 1] = blockCount;
        
        memcpy(U, [mSalt bytes], [mSalt length]);
        
        CCHmac(kCCHmacAlgSHA1, passPhraseBytes, passPhraseLength, [mSalt bytes], [mSalt length], mac);
        
        for (i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        {
            outputBytes[i] ^= mac[i];
            U[i] = mac[i];
        }
        
        for (int iteration = 1; iteration < iterations; iteration++)
        {
            CCHmac(kCCHmacAlgSHA1, passPhraseBytes, passPhraseLength, U, CC_SHA1_DIGEST_LENGTH, mac);
            for (i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
            {
                outputBytes[i] ^= mac[i];
                U[i] = mac[i];
            }
        }
        
        int bytesNeeded = (int)[deriveBytes length] - generatedBytes;
        int bytesToCopy = MIN(bytesNeeded, CC_SHA1_DIGEST_LENGTH);
        [deriveBytes replaceBytesInRange:NSMakeRange(generatedBytes, bytesToCopy) withBytes:outputBytes];
        generatedBytes += bytesToCopy;
    }
}

+ (void)deriveKey:(NSMutableData *)key
            andIV:(NSMutableData *)initialValue
     fromPassword:(NSString *)password
          andSalt:(NSData *)salt
{
    /*  Some Windows applications use a key size of kCCKeySizeAES128 (16)
        while others may have a custom implementation using a key size of 32.
        Modify the values here to the expected size. */
    
    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:(kCCKeySizeAES256 + kCCBlockSizeAES128)];
    
    [RFC2898DeriveBytes deriveBytes:buffer fromPassword:password andSalt:salt];
    
    [key setLength:kCCKeySizeAES256];
    [initialValue setLength:kCCBlockSizeAES128];
    
    [buffer getBytes:[key mutableBytes] range:NSMakeRange(0, kCCKeySizeAES256)];
    [buffer getBytes:[initialValue mutableBytes] range:NSMakeRange(kCCKeySizeAES256, kCCBlockSizeAES128)];
}

@end
