//
//  KeyPair.m
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "KeyPair.h"
#import "libyee_signer.h"
#import "ErrorUtils.h"

@interface KeyPair ()

@property (nonatomic) unsigned int* pointer;

@end

@implementation KeyPair

const unsigned int MINI_SECRET_KEY_LENGTH = 32;
const unsigned int SECRET_KEY_LENGTH = 64;
const unsigned int PUBLIC_KEY_LENGTH = 32;
const unsigned int SIGNATURE_LENGTH = 64;

+ (KeyPair *) fromMiniSecretKey:(NSData* ) miniSecretKey error:(NSError **)error{
        
    unsigned int err = 0;
    unsigned int* pointer = yee_signer_key_pair_from_mini_secret_key(miniSecretKey.bytes, (unsigned int) miniSecretKey.length, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    KeyPair* keyPair = [KeyPair alloc];
    keyPair.pointer = pointer;
    return keyPair;
}

+ (KeyPair *) fromSecretKey:(NSData* ) secretKey error:(NSError **)error{
        
    unsigned int err = 0;
    unsigned int* pointer = yee_signer_key_pair_from_secret_key(secretKey.bytes, (unsigned int) secretKey.length, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    KeyPair* keyPair = [KeyPair alloc];
    keyPair.pointer = pointer;
    return keyPair;
}

- (NSData *) publicKey:(NSError **)error {
    
    unsigned int err = 0;
    unsigned char result[PUBLIC_KEY_LENGTH];
    yee_signer_public_key(self.pointer, result, PUBLIC_KEY_LENGTH, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    NSData* data = [NSData dataWithBytes:(const void *)result length:PUBLIC_KEY_LENGTH];
    return data;
}

- (NSData *) secretKey:(NSError **)error {
    
    unsigned int err = 0;
    unsigned char result[SECRET_KEY_LENGTH];
    yee_signer_secret_key(self.pointer, result, SECRET_KEY_LENGTH, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    NSData* data = [NSData dataWithBytes:(const void *)result length:SECRET_KEY_LENGTH];
    return data;
}

- (NSData *) sign: (NSData *)message ctx: (NSData *)ctx error:(NSError **)error{
    
    unsigned int err = 0;
    unsigned char result[SIGNATURE_LENGTH];
    yee_signer_sign(self.pointer, message.bytes, (unsigned int)message.length,
                    result, SIGNATURE_LENGTH, ctx.bytes, (unsigned int)ctx.length, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    NSData* data = [NSData dataWithBytes:(const void *)result length:SIGNATURE_LENGTH];
    return data;
}

- (void) free:(NSError **)error{
    
    unsigned int err = 0;
    yee_signer_verifier_free(self.pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
    }
}

@end
