#!/usr/bin/env python

'''
This script validates users.toml for several aspects
The script requires at least Python 3.11

Written by Mario Voigt (vmario89) - Stadtfabrikanten e.V. - 2024

ToDos
- enter bffh.dhall path to check roles against users.toml. If our toml contains roles, which bffh does not know, we should also warn!
'''

import argparse
import os
import sys
import tomllib
import uuid

'''
cardkeys for FabAccess use Uuid format in Version v4 (see https://docs.rs/uuid/latest/uuid/struct.Uuid.html)
allowed formattings:
- simple: a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8
- hyphenated: a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8
- urn: urn:uuid:A1A2A3A4-B1B2-C1C2-D1D2-D3D4D5D6D7D8
- braced: {a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8}
'''
def is_valid_uuid(val):
    try:
        _uuid = uuid.UUID(val, version=4)
        return True
    except ValueError:
        return False

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=str, help="path of users.toml user database file")
    args = parser.parse_args()

    if args.db is None:
        usertoml = args.db
        print("No custom users.toml given. You may add it with '--db </path/to/users.toml>'")
        default_usertoml = "/etc/bffh/users.toml"
        if os.path.isfile(default_usertoml):
            print("Found default file: {}. Using this ...".format(default_usertoml))
            usertoml = default_usertoml
        else:
            print("Error: no (default) users.toml file given or found. Cannot continue!".format(default_usertoml))
            sys.exit(1)

    countUsers = 0
    countUsersWithoutCardkeyOrPassword = 0
    uniqueRoles = []
    countUserWithoutRoles = 0
    countUserWithDuplicateRoles = 0
    countPassword = 0
    countPasswordUnencrypted = 0
    countPasswordEncrypted = 0
    countPasswordDuplicates = 0
    countCardkey = 0
    countCardkeyInvalid = 0
    countCardkeyDuplicates = 0
    countUnknownKeys = 0

    countWarnings = 0

    #a definition of valid keys within a user section of FabAccess
    knownKeys = ['roles', 'passwd', 'cardkey']

    print("{} Checking database {}\n".format("*"*25, "*"*25))

    file_stats = os.stat(usertoml)
    #print(file_stats)
    print("Database size: {} Bytes ({:0.5f} MB)".format(file_stats.st_size, file_stats.st_size / (1024 * 1024)))
    if file_stats.st_size == 0:
        print("Error: File size is zero! Database is corrupted!")
        sys.exit(1)

    print("\n")

    with open(usertoml, "rb") as f:
        try:
            data = tomllib.load(f)
        except Exception as e:
            if "Cannot declare" in str(e) and "twice" in str(e):
                print("Error: found at least one duplicate user. Cannot parse database. Please fix and try again. Message: {}".format(str(e)))
            elif "Invalid value" in str(e):
                print("Error: Some user contains a key without value (e.g. 'passwd = '). Cannot parse database. Please fix and try again. Message: {}".format(str(e)))
            elif "Expected '=' after a key" in str(e):
                print("Error: Found an incorrect key/value mapping. Cannot parse database. Please fix and try again. Message: {}".format(str(e)))
            else:
                print(str(e))
            sys.exit(1)

        passwds = []
        cardkeys = []

        for user in data:
            print("--- {}".format(user))

            for key in data[user].keys():
                if key not in knownKeys:
                    print("Warning: User '{}' contains unknown key '{}' (will be ignored by BFFH server)".format(user, key))
                    countWarnings += 1
                    countUnknownKeys += 1

            if "roles" in data[user]:
                roles = data[user]["roles"]
                if type(roles) != list:
                    print("Warning: roles for user '{}' are not defined as array! BFFH will fail to load".format(user))
                    countWarnings += 1
                userRoles = []
                for role in roles:
                    # check if a role is duplicate in the array for the user
                    if role not in userRoles:
                        userRoles.append(role)
                    else:
                        print("Warning: duplicate role '{}' for user '{}'".format(role, user))
                        countUserWithDuplicateRoles += 1
                        countWarnings += 1
                    # collect all unique roles for the toml file
                    if role not in uniqueRoles:
                        uniqueRoles.append(role)
                if roles is None: #if role key is defined but empty
                    countUserWithoutRoles += 1
            else: #if role key is not existent
                countUserWithoutRoles += 1

            if "passwd" in data[user]:
                passwd = data[user]["passwd"]
                countPassword += 1
                if type(passwd) != str:
                    print("Warning: password for user '{}' is not defined as string! BFFH will fail to load".format(user))
                    countWarnings += 1
                elif passwd.startswith("$argon2") is False:
                    print("Warning: Password for user '{}' is not encrypted!".format(user))
                    countWarnings += 1
                    countPasswordUnencrypted += 1
                else:
                    countPasswordEncrypted += 1
                if passwd in passwds:
                    print("Warning: password for user '{}' is already in use by other user(s). That might be insecure".format(user))
                    countPasswordDuplicates += 1
                    countWarnings += 1
                passwds.append(passwd)

            if "cardkey" in data[user]:
                cardkey = data[user]["cardkey"]
                if type(passwd) != str:
                    print("Warning: cardkey for user '{}' is not defined as string! BFFH will fail to load".format(user))
                    countWarnings += 1
                elif is_valid_uuid(cardkey) is False:
                    print("Warning: cardkey for user '{}' contains invalid cardkey (no UUID v4)".format(user))
                    countCardkeyInvalid += 1
                    countWarnings += 1
                if cardkey in cardkeys:
                    print("Warning: cardkey for user '{}' is already in use by other user(s). That might be insecure".format(user))
                    countCardkeyDuplicates += 1
                    countWarnings += 1

                cardkeys.append(cardkey)

                countCardkey += 1

            if "passwd" not in data[user] and "cardkey" not in data[user]:
                countUsersWithoutCardkeyOrPassword += 1

            countUsers += 1
            print("\n")

        print("\n")

        if countUsers == 0:
            print("Error: Database does not contain any users!")
            sys.exit(1)

        print("{} Database statistics {}\n".format("*"*25, "*"*25))
        print("- Total users: {}".format(countUsers))
        print("- Total unique roles: {}".format(len(uniqueRoles)))
        print("- Total passwords: {} (encrypted: {}, unencrypted: {}, duplicates: {})".format(countPassword, countPasswordEncrypted, countPasswordUnencrypted, countPasswordDuplicates))
        print("- Total cardkeys: {} (duplicates: {})".format(countCardkey, countCardkeyDuplicates))

        print("\n")

        print("{} Important information {}\n".format("*"*25, "*"*25))
        if countUnknownKeys > 0:
            print("- {} unknown keys (will be ignored by BFFH server)".format(countUnknownKeys))

        if countUserWithoutRoles > 0:
            print("- {} users without any roles. They won't be able to do something as client!".format(countUserWithoutRoles))

        if countUserWithDuplicateRoles > 0:
            print("- {} users with duplicate roles. Please clean up!".format(countUserWithDuplicateRoles))

        if len(uniqueRoles) == 0:
            print("- Globally, there are no roles assigned for any user. They won't be able to do something as client!")

        if countCardkeyInvalid > 0:
            print("- {} invalid cardkeys in your database. They won't be able to authenticate at BFFH server by keycard!".format(countCardkeyInvalid))

        if countUsersWithoutCardkeyOrPassword > 0:
            print("- {} users without both: password and cardkey. They won't be able to login anyhow!".format(countUsersWithoutCardkeyOrPassword))

        if countWarnings > 0:
            print("- {} warnings in total. You might need to optimize your user database!".format(countWarnings))

if __name__ == "__main__":
    main()
