//
//  Transaction.h
//  YeeSigner
//
//  Created by GB on 2020/7/10.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Call.h"

@interface Transaction : NSObject

@property (nonatomic) unsigned int* pointer;

+ (Transaction *) buildTx:(NSData* ) secretKey nonce:(u_long) nonce period:(u_long) period current: (u_long) current current_hash: (NSData* ) current_hash call: (Call *) call error:(NSError **) error;

+ (Transaction *) decode: (NSData* )raw error:(NSError **) error;

- (NSData *) encode:(NSError **)error;

- (BOOL) verify: (NSData *)currentHash error:(NSError **)error;

- (void) free:(NSError **)error;

@end
