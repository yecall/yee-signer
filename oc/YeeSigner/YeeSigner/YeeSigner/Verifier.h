//
//  Verifier.h
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Verifier : NSObject

+ (Verifier *) fromPublicKey:(NSData* ) publicKey error:(NSError **)error;

- (BOOL) verify: (NSData *)signature message: (NSData *) message ctx: (NSData *)ctx error:(NSError **)error;

- (void) free:(NSError **)error;

@end
