//
//  KeyPair.h
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KeyPair : NSObject

+ (KeyPair *) fromMiniSecretKey:(NSData* ) miniSecretKey error:(NSError **)error;

+ (KeyPair *) fromSecretKey:(NSData* ) secretKey error:(NSError **)error;

- (NSData *) publicKey:(NSError **)error;

- (NSData *) secretKey:(NSError **)error;

- (NSData *) sign: (NSData *)message ctx: (NSData *)ctx error:(NSError **)error;

- (void) free:(NSError **)error;

@end
