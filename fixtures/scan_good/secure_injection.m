// Objective-C injection fixtures (good): parameterized FMDB calls with ?
// placeholders + bind arrays, named-parameter queries, static commands and
// numeric-only stringWithFormat: all stay quiet.
#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface SecureDB : NSObject
@property (nonatomic, strong) id db;
- (void)run;
@end

@implementation SecureDB

- (void)run {
    // Parameterized query with ? placeholder and a bind array
    [self.db executeQuery:@"SELECT * FROM users WHERE id = ?" withArgumentsInArray:@[self.uid]];

    // executeUpdate with a bind array
    [self.db executeUpdate:@"DELETE FROM logs WHERE id = ?" withArgumentsInArray:@[self.logId]];

    // Static query, no user input
    [self.db executeQuery:@"SELECT COUNT(*) FROM orders"];

    // Named-parameter query passed directly
    [self.db executeQuery:@"UPDATE t SET v = :val WHERE id = :id" withParameterDictionary:self.params];

    // Parameter values supplied separately
    [self.db executeUpdate:sql withArgumentsInArray:args];

    // Static shell command, no interpolation
    system("ls -la");

    // NSTask with a static argument array, no shell string
    [task setArguments:@[@"/bin/ls", @"-l"]];

    // Numeric format has no %@ object placeholder and no SQL keyword
    NSString *msg = [NSString stringWithFormat:@"%d users loaded", count];
    [self.db executeQuery:@"SELECT COUNT(*) FROM users"];
}

@end
