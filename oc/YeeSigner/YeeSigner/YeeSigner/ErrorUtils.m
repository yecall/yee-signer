//
//  ErrorUtils.m
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "ErrorUtils.h"

@implementation ErrorUtils

+ (NSError* ) error:(unsigned int )err {
    NSDictionary* dict = @{
        @1: @"unknown",
        @2: @"invalid mini secret key",
        @3: @"invalid secret key",
        @4: @"invalid public key",
        @5: @"invalid signature",
    };
    
    NSString *message = [dict objectForKey:@(err)];
    message = message ==nil ? @"unknown" : message;
    
    return [NSError errorWithDomain:@"YeeSigner" code:err userInfo:@{@"message": message}];
}

@end
