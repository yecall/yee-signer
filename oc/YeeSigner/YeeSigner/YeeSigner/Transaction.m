//
//  Transaction.m
//  YeeSigner
//
//  Created by GB on 2020/7/10.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "Transaction.h"
#import "libyee_signer.h"
#import "ErrorUtils.h"
#import "Call.h"

@interface Transaction ()

@end

@implementation Transaction

+ (Transaction *) buildTx:(NSData* ) secretKey nonce:(u_long) nonce period:(u_long) period current: (u_long) current current_hash: (NSData* ) current_hash call: (Call *) call error:(NSError **) error{
    
    unsigned int err = 0;
    
    unsigned int* pointer = yee_signer_build_tx(secretKey.bytes, (unsigned int)secretKey.length, nonce, period, current, current_hash.bytes, (unsigned int)current_hash.length, call.pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    Transaction *tx = [Transaction alloc];
    tx.pointer = pointer;
    
    return tx;
    
}

+ (Transaction *) decode: (NSData* )raw error:(NSError **) error{
    
    unsigned int err = 0;
    
    unsigned int* pointer = yee_signer_tx_decode(raw.bytes, (unsigned int)raw.length, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    Transaction *tx = [Transaction alloc];
    tx.pointer = pointer;
    
    return tx;
}

- (NSData *) encode:(NSError **)error {
    
    unsigned int err = 0;
    
    unsigned int* vec_pointer = yee_signer_tx_encode(self.pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    unsigned int vec_len = yee_signer_vec_len(vec_pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        yee_signer_vec_free(vec_pointer, &err);
        return nil;
    }
    
    unsigned char buffer[vec_len];
    yee_signer_vec_copy(vec_pointer, buffer, vec_len, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        yee_signer_vec_free(vec_pointer, &err);
        return nil;
    }
    
    // free vec
    yee_signer_vec_free(vec_pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    NSData* data = [NSData dataWithBytes:(const void *)buffer length:vec_len];
    return data;
}

- (BOOL) verify: (NSData *)currentHash error:(NSError **)error{
    
    unsigned int err = 0;
    
    yee_signer_verify_tx(self.pointer, currentHash.bytes, (unsigned int)currentHash.length, &err);
    return err == 0 ? YES : NO;
}

- (void) free:(NSError **)error{
    
    unsigned int err = 0;
    yee_signer_tx_free(self.pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
    }
}

@end
