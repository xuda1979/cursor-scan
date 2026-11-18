// Objective-C injection fixtures (bad): SQL built with stringWithFormat:
// %@ object placeholders and stringByAppendingString: concatenation fed to
// FMDB / sqlite3 receivers, plus system()/popen()/NSTask -c command strings.
#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface BadDB : NSObject
@property (nonatomic, strong) id db;
- (void)run;
@end

@implementation BadDB

- (void)run {
    // 1: FMDB executeQuery with a format-built query carrying %@
    [self.db executeQuery:@"SELECT * FROM users WHERE id = %@", self.uid];

    // 2: FMDB executeUpdate with a format-built DELETE
    [self.db executeUpdate:@"DELETE FROM logs WHERE id = %@", self.logId];

    // 3: FMDB executeQuery with role filter built by stringWithFormat:
    [self.db executeQuery:[NSString stringWithFormat:@"SELECT name FROM accounts WHERE role = %@", self.role]];

    // 4: FMDB executeStatement fed via initWithFormat:
    [self.db executeStatement:[[NSString alloc] initWithFormat:@"INSERT INTO audit VALUES (%@)", self.payload]];

    // 5: sqlite3_exec with a UTF8 format-built query
    sqlite3_exec(self.dbHandle, [[NSString stringWithFormat:@"SELECT * FROM t WHERE name = %@", self.name] UTF8String], nil, nil, nil);

    // 6: assignment form - query assembled on its own line
    NSString *sql = [NSString stringWithFormat:@"UPDATE profiles SET bio = %@ WHERE id = %@", self.bio, self.userId];
    [self.db executeUpdate:sql];

    // 7: stringByAppendingString: concatenation into executeQuery
    [self.db executeQuery:[@"SELECT * FROM books WHERE isbn = " stringByAppendingString:self.isbn]];

    // 8: system() with a format-built command
    system([[NSString stringWithFormat:@"ping -c 1 %@", self.host] UTF8String]);

    // 9: popen() with a format-built command
    popen([[NSString stringWithFormat:@"ls -la %@", self.dir] UTF8String], "r");

    // 10: NSTask /bin/sh -c launch args built through a format call
    [task setArguments:@[@"-c", [NSString stringWithFormat:@"cmd %@", self.arg]]];
}

@end
