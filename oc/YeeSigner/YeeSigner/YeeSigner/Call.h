//
//  Call.h
//  YeeSigner
//
//  Created by GB on 2020/7/10.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Call : NSObject

@property (nonatomic) unsigned int* pointer;

+ (Call *) buildCall:(NSString* ) json error:(NSError **) error;

- (void) free:(NSError **)error;

@end

