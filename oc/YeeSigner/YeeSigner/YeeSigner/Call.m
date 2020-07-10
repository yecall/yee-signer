//
//  Call.m
//  YeeSigner
//
//  Created by GB on 2020/7/10.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "Call.h"
#import "libyee_signer.h"
#import "ErrorUtils.h"

@interface Call ()

@end

@implementation Call

+ (Call *) buildCallBalanceTransfer:(NSData* ) address value:(u_long) value error:(NSError **) error {
    
    unsigned int module_holder = 0;
    unsigned int method_holder = 0;
    unsigned int err = 0;
    
    unsigned int* pointer = yee_signer_build_call_balance_transfer(address.bytes, (unsigned int)address.length, value, &module_holder, &method_holder, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    Call* call = [Call alloc];
    call.pointer = pointer;
    call.module = module_holder;
    call.method = method_holder;
    return call;
    
}

- (void) free:(NSError **)error {
    
    unsigned int err = 0;
    yee_signer_call_free(self.pointer, self.module, self.method, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
    }
}

@end
