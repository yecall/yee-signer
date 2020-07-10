//
//  Verifier.m
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "Verifier.h"
#import "libyee_signer.h"
#import "ErrorUtils.h"

@interface Verifier ()

@property (nonatomic) unsigned int* pointer;

@end

@implementation Verifier

+ (Verifier *) fromPublicKey:(NSData* ) publicKey error:(NSError **)error{
        
    unsigned int err = 0;
    unsigned int* pointer = yee_signer_verifier_from_public_key(publicKey.bytes, (unsigned int) publicKey.length, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    Verifier* verifier = [Verifier alloc];
    verifier.pointer = pointer;
    return verifier;
}

- (BOOL) verify: (NSData *)signature message: (NSData *) message ctx: (NSData *) ctx error:(NSError **)error{
    
    unsigned int err = 0;
    yee_signer_verify(self.pointer, signature.bytes, (unsigned int)signature.length, message.bytes, (unsigned int)message.length, ctx.bytes, (unsigned int) ctx.length, &err);
    return err == 0 ? YES : NO;
}

- (void) free:(NSError **)error{
    
    unsigned int err = 0;
    yee_signer_verifier_free(self.pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
    }
}

@end
