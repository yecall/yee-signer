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

+ (Call *) buildCall:(NSString* ) json error:(NSError **) error{
    
    NSData* jsonData = [json dataUsingEncoding:NSUTF8StringEncoding];

    unsigned int err = 0;
    
    unsigned int* pointer = yee_signer_build_call(jsonData.bytes, (unsigned int)jsonData.length, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
        return nil;
    }
    
    Call* call = [Call alloc];
    call.pointer = pointer;
    return call;
}

- (void) free:(NSError **)error {
    
    unsigned int err = 0;
    yee_signer_call_free(self.pointer, &err);
    if(err > 0) {
        *error = [ErrorUtils error:err];
    }
}

@end
