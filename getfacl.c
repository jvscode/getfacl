/*

getfacl -- get file access control lists on Mac OS X

compile with:

gcc -Wall -O3 -o getfacl getfacl.c

Further getfacl implementations (Linux, FreeBSD, Mac OS X):

- http://git.savannah.gnu.org/cgit/acl.git/tree/getfacl/getfacl.c (Linux)
- http://www.freebsd.org/cgi/cvsweb.cgi/src/bin/getfacl/getfacl.c?rev=1.12.12.1;content-type=text%2Fplain (FreeBSD)
- File Access Control Lists (GUI, sample code), http://www.fernlightning.com/doku.php?id=randd:acl:start (Mac OS X)

*/

/* Copyright statement for FreeBSD-related code */

/*-
 *
 * See: http://www.freebsd.org/cgi/cvsweb.cgi/src/bin/getfacl/getfacl.c?rev=1.12.12.1;content-type=text%2Fplain
 *
 * Copyright (c) 1999, 2001, 2002 Robert N M Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * getfacl -- POSIX.1e utility to extract ACLs from files and directories
 * and send the results to stdout
 */


/* Copyright statement for Apple-related code */

/*
 * Copyright (c) 1989, 1993, 1994
 *  The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Michael Fischbein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/* Copyright statement for code written by jv */
/*
* License: The MIT License
* URL: http://www.opensource.org/licenses/mit-license.php
* Copyright (c) 2010 jv
*/


#include <sys/cdefs.h>
/*__FBSDID("$FreeBSD: src/bin/getfacl/getfacl.c,v 1.12.12.1 2010/02/10 00:26:20 kensmith Exp $");*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/acl.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* additional includes for Mac OS X version of getfacl */

#include <membership.h>
#include <membershipPriv.h>

/*
# membershipPriv.h
if [[ ! -e '/usr/include/membershipPriv.h' ]]; then
   curl -L -o membershipPriv.h 'http://www.opensource.apple.com/source/Libinfo/Libinfo-324.1/membership.subproj/membershipPriv.h?txt'
   sudo cp -i membershipPriv.h /usr/include
fi
*/


#define PATHBUFSIZE 5000

/* FreeBSD */
static char *getgname(gid_t gid);
static char *getuname(uid_t uid);

/* FreeBSD modified */
/* added write_null_byte and verbose */
static int print_acl_from_stdin(acl_type_t type, int write_null_byte, int not_follow_symlink, int verbose);
static int print_acl_from_stdin_null(acl_type_t type, int write_null_byte, int not_follow_symlink, int verbose);

/* Apple */
static char *uuid_to_name(uuid_t *uu); 
static void printacl(acl_t acl, int isdir, int verbose);   /* added verbose */

static void usage(void);


static const char help_msg[] =
   "\n"
   "getfacl - get Access Control List (ACL) information\n"
   "\n"
   "usage:   getfacl [-0dhlvz] [file ...]\n"
   "\n"
   "-0:  read null-terminated file paths from stdin\n"
   "-d   get the default ACL of a directory instead of the access ACL (but see ACL_TYPE_DEFAULT in <sys/acl.h>)\n"
   "-h   display help message\n"
   "-l   get the ACL from a symbolic link itself instead of its target (see apropos acl_get_link_np)\n"
   "-v   enable verbose output\n"
   "-z   write null-terminated output to stdout in the format: /path/to/file\\000...ACL data...\\000\n"
   "\n";


/* 

code to print access control list information (Mac OS X)

from: http://www.opensource.apple.com/source/file_cmds/file_cmds-202.2/ls
      http://www.opensource.apple.com/source/file_cmds/file_cmds-202.2/ls/ls.c
      http://www.opensource.apple.com/source/file_cmds/file_cmds-202.2/ls/print.c

*/

static int f_numericonly;   /* don't convert uid/gid to name; taken from ls.c */

/*
 * print access control list
 * taken from print.c
 * added verbose to printacl()
 */

static struct {
    acl_perm_t  perm;
    char        *name;
    int     flags;
#define ACL_PERM_DIR    (1<<0)
#define ACL_PERM_FILE   (1<<1)
} acl_perms[] = {
    {ACL_READ_DATA,     "read",     ACL_PERM_FILE},
    {ACL_LIST_DIRECTORY,    "list",     ACL_PERM_DIR},
    {ACL_WRITE_DATA,    "write",    ACL_PERM_FILE},
    {ACL_ADD_FILE,      "add_file", ACL_PERM_DIR},
    {ACL_EXECUTE,       "execute",  ACL_PERM_FILE},
    {ACL_SEARCH,        "search",   ACL_PERM_DIR},
    {ACL_DELETE,        "delete",   ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_APPEND_DATA,   "append",   ACL_PERM_FILE},
    {ACL_ADD_SUBDIRECTORY,  "add_subdirectory", ACL_PERM_DIR},
    {ACL_DELETE_CHILD,  "delete_child", ACL_PERM_DIR},
    {ACL_READ_ATTRIBUTES,   "readattr", ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_WRITE_ATTRIBUTES,  "writeattr",    ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_READ_EXTATTRIBUTES, "readextattr", ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_WRITE_EXTATTRIBUTES, "writeextattr", ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_READ_SECURITY, "readsecurity", ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_WRITE_SECURITY,    "writesecurity", ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_CHANGE_OWNER,  "chown",    ACL_PERM_FILE | ACL_PERM_DIR},
    {0, NULL, 0}
};

static struct {
    acl_flag_t  flag;
    char        *name;
    int     flags;
} acl_flags[] = {
    {ACL_ENTRY_FILE_INHERIT,    "file_inherit",     ACL_PERM_DIR},
    {ACL_ENTRY_DIRECTORY_INHERIT,   "directory_inherit",    ACL_PERM_DIR},
    {ACL_ENTRY_LIMIT_INHERIT,   "limit_inherit",    ACL_PERM_FILE | ACL_PERM_DIR},
    {ACL_ENTRY_ONLY_INHERIT,    "only_inherit",     ACL_PERM_DIR},
    {0, NULL, 0}
};

static char *
uuid_to_name(uuid_t *uu) 
{
  int is_gid = -1;
  struct group *tgrp = NULL;
  struct passwd *tpass = NULL;
  char *name = NULL;
  uid_t id;


#define MAXNAMETAG (MAXLOGNAME + 6) /* + strlen("group:") */
  name = (char *) malloc(MAXNAMETAG);
  
  if (NULL == name)
      err(1, "malloc");

    if (!f_numericonly) {
  if (0 != mbr_uuid_to_id(*uu, &id, &is_gid))
      goto errout;
    }
  
  switch (is_gid) {
  case ID_TYPE_UID:
      tpass = getpwuid(id);
      if (!tpass) {
          goto errout;
      }
      snprintf(name, MAXNAMETAG, "%s:%s", "user", tpass->pw_name);
      break;
  case ID_TYPE_GID:
      tgrp = getgrgid((gid_t) id);
      if (!tgrp) {
          goto errout;
      }
      snprintf(name, MAXNAMETAG, "%s:%s", "group", tgrp->gr_name);
      break;
  default:
        goto errout;
  }
  return name;
 errout:
    if (0 != mbr_uuid_to_string(*uu, name)) {
        fprintf(stderr, "Unable to translate qualifier on ACL\n");
        strcpy(name, "<UNKNOWN>");
    }
  return name;
}


static void
printacl(acl_t acl, int isdir, int verbose)
{
    acl_entry_t entry = NULL;
    int     index;
    uuid_t      *applicable;
    char        *name = NULL;
    acl_tag_t   tag;
    acl_flagset_t   flags;
    acl_permset_t   perms;
    char        *type;
    int     i, first;
    

    for (index = 0;
         acl_get_entry(acl, entry == NULL ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &entry) == 0;
         index++) {
        if ((applicable = (uuid_t *) acl_get_qualifier(entry)) == NULL)
            continue;
        if (acl_get_tag_type(entry, &tag) != 0)
            continue;
        if (acl_get_flagset_np(entry, &flags) != 0)
            continue;
        if (acl_get_permset(entry, &perms) != 0)
            continue;
        name = uuid_to_name(applicable);
        acl_free(applicable);

        switch(tag) {
        case ACL_EXTENDED_ALLOW:
            type = "allow";
            break;
        case ACL_EXTENDED_DENY:
            type = "deny";
            break;
        default:
            type = "unknown";
        }

        if (verbose == 1)
        {
           (void)printf(" %d: %s%s %s ",
               index,
               name,
               acl_get_flag_np(flags, ACL_ENTRY_INHERITED) ? " inherited" : "",type);
        }else{
           (void)printf("%s%s %s ",
               name,
               acl_get_flag_np(flags, ACL_ENTRY_INHERITED) ? " inherited" : "",type);
        }

        if (name)
            free(name);

        for (i = 0, first = 0; acl_perms[i].name != NULL; i++) {
            if (acl_get_perm_np(perms, acl_perms[i].perm) == 0)
                continue;
            if (!(acl_perms[i].flags & (isdir ? ACL_PERM_DIR : ACL_PERM_FILE)))
                continue;
            (void)printf("%s%s", first++ ? "," : "", acl_perms[i].name);
        }
        for (i = 0; acl_flags[i].name != NULL; i++) {
            if (acl_get_flag_np(flags, acl_flags[i].flag) == 0)
                continue;
            if (!(acl_flags[i].flags & (isdir ? ACL_PERM_DIR : ACL_PERM_FILE)))
                continue;
            (void)printf("%s%s", first++ ? "," : "", acl_flags[i].name);
        }
            
        (void)putchar('\n');
    }

}


static char *
getuname(uid_t uid)
{
    struct passwd *pw;
    static char uids[10];

    if ((pw = getpwuid(uid)) == NULL) {
        (void)snprintf(uids, sizeof(uids), "%u", uid);
        return (uids);
    } else
        return (pw->pw_name);
}

static char *
getgname(gid_t gid)
{
    struct group *gr;
    static char gids[10];

    if ((gr = getgrgid(gid)) == NULL) {
        (void)snprintf(gids, sizeof(gids), "%u", gid);
        return (gids);
    } else
        return (gr->gr_name);
}


static int
print_acl_from_stdin(acl_type_t type, int write_null_byte, int not_follow_symlink, int verbose)
{
    if(isatty(STDIN_FILENO))
    {
        /* fprintf(stderr, "%s", help_msg); */
        fprintf(stderr, "\nNo data stream available from stdin. \n\nTry: getfacl -h\n\n");
        exit(1);
    }

    int error = 0;
    int count = 0;
    char    *p, pathname[PATH_MAX];

    while (fgets(pathname, (int)sizeof(pathname), stdin)) {

        if ((p = strchr(pathname, '\n')) != NULL)
            *p = '\0';

           struct stat sp;

           if (not_follow_symlink == 1)
              error = lstat(pathname, &sp);
           else
              error = stat(pathname, &sp);

           if (error != 0) 
           {
              warn("%s", pathname);
              return(-1);
           }

           acl_t acl = NULL;

           if (not_follow_symlink == 1)
              acl = acl_get_link_np(pathname, type);
           else
              acl = acl_get_file(pathname, type);

           if (acl == NULL)
           {
              fprintf(stderr,"No ACL: %s\n", pathname);
              /* pathname[0] = '\0'; */
              acl_free(acl);
              continue;
           }

           if (write_null_byte == 1)
           {
              if (verbose == 1)
              {
                 printf("file: %s%c", pathname, 0);
                 printf("user: %i %s\n"
                        "goup: %i %s\n"
                        "perms: %o\n"
                        , 
                        sp.st_uid, getuname(sp.st_uid),
                        sp.st_gid, getgname(sp.st_gid),
                        sp.st_mode
                 );
              }else{
                 printf("%s%c", pathname, 0);
              }
              printacl(acl, S_ISDIR(sp.st_mode), verbose);    /* if S_ISDIR() returns 1 it's a directory */
              putchar(0);
           }else{
              if (verbose == 1)
              {
                 count == 0 ? ++count : putchar('\n');
                 printf("file: %s\n"
                        "user: %i %s\n"
                        "goup: %i %s\n"
                        "perms: %o\n"
                        , 
                        pathname,
                        sp.st_uid, getuname(sp.st_uid),
                        sp.st_gid, getgname(sp.st_gid),
                        sp.st_mode
                 );
                 printacl(acl, S_ISDIR(sp.st_mode), verbose);
              }else{
                 count == 0 ? ++count : putchar('\n');
                 printf("%s\n", pathname);
                 printacl(acl, S_ISDIR(sp.st_mode), verbose);   
              }
           }

           acl_free(acl);

    }

    return(0);
}



static int
print_acl_from_stdin_null(acl_type_t type, int write_null_byte, int not_follow_symlink, int verbose)
{

    if(isatty(STDIN_FILENO))
    {
        fprintf(stderr, "\nNo data stream available from stdin. \n\nTry: getfacl -h\n\n");
        exit(1);
    }

   int error = 0;
   int singlechar = 0;
   char *pathnamebuf = 0;
   int count = 0;

   pathnamebuf = calloc (PATHBUFSIZE, sizeof(char));

   if (pathnamebuf == NULL) 
   { 
      fprintf(stderr, "...allocating pathnamebuf failed ...\n");
      exit(1);
   }

   size_t buf_index = 0;
   size_t currentBufSize = PATHBUFSIZE;
   size_t currentBufSizeMinusOne = currentBufSize - 1;

   while ((singlechar = getchar()) != EOF) 
   {

      if (buf_index == currentBufSizeMinusOne)
      {
          currentBufSize = currentBufSize * 2;
          currentBufSizeMinusOne = currentBufSize - 1;
          pathnamebuf = reallocf(pathnamebuf, currentBufSize);
          if (pathnamebuf == NULL) 
          { 
             fprintf(stderr, "... reallocating pathnamebuf failed ...\n");
             return(1);
          }

      }

      if (singlechar == '\0') 
      { 

           pathnamebuf[buf_index] = singlechar;

           struct stat sp;

           if (not_follow_symlink == 1)
              error = lstat(pathnamebuf, &sp);
           else
              error = stat(pathnamebuf, &sp);

           if (error != 0) 
           {
              warn("%s", pathnamebuf);
              return(-1);
           }

           acl_t acl = NULL;

           if (not_follow_symlink == 1)
              acl = acl_get_link_np(pathnamebuf, type);
           else
              acl = acl_get_file(pathnamebuf, type);

           if (acl == NULL)
           {
              fprintf(stderr,"No ACL: %s\n", pathnamebuf);
              /* pathnamebuf[0] = '\0'; */
              buf_index = 0;
              acl_free(acl);
              continue;
           }

           if (write_null_byte == 1)
           {
              if (verbose == 1)
              {
                 printf("file: %s%c", pathnamebuf, 0);
                 printf("user: %i %s\n"
                        "goup: %i %s\n"
                        "perms: %o\n"
                        , 
                        sp.st_uid, getuname(sp.st_uid),
                        sp.st_gid, getgname(sp.st_gid),
                        sp.st_mode
                 );
              }else{
                 printf("%s%c", pathnamebuf, 0);
              }
              printacl(acl, S_ISDIR(sp.st_mode), verbose);    
              putchar(0);
           }else{
              if (verbose == 1)
              {
                 count == 0 ? ++count : putchar('\n');
                 printf("file: %s\n"
                        "user: %i %s\n"
                        "goup: %i %s\n"
                        "perms: %o\n"
                        , 
                        pathnamebuf,
                        sp.st_uid, getuname(sp.st_uid),
                        sp.st_gid, getgname(sp.st_gid),
                        sp.st_mode
                 );
                 printacl(acl, S_ISDIR(sp.st_mode), verbose);
              }else{
                 count == 0 ? ++count : putchar('\n');
                 printf("%s\n", pathnamebuf);
                 printacl(acl, S_ISDIR(sp.st_mode), verbose);   
              }
          }

           acl_free(acl);


         buf_index = 0;

      } else {

         pathnamebuf[buf_index] = singlechar;
         ++buf_index;

      }


   }

  free(pathnamebuf);

  return 0;
}


static void
usage(void)
{
   printf("%s", help_msg);
   fflush(stdout);
}



int
main(int argc, char *argv[])
{

   acl_type_t  type = ACL_TYPE_EXTENDED;

   int ch, i;

   int read_null_byte = 0;
   int write_null_byte = 0;
   int not_follow_symlink = 0;
   int error = 0;
   int verbose = 0;
   int count = 0;

   while ((ch = getopt(argc, argv, "0dhlvz")) != -1)
   {
      switch(ch) 
      {
         case '0':
             read_null_byte = 1;
             break;
         case 'd':
             type = ACL_TYPE_DEFAULT;
             break;
         case 'h':
             usage();
             return(0);
         case 'l':
             not_follow_symlink = 1;
             break;
         case 'v':
             verbose = 1;
             break;
         case 'z':
             write_null_byte = 1;
             break;
         default:
             fprintf(stderr, "%s", help_msg);
             return(-1);
      }
   }

   argc -= optind;
   argv += optind;

   if ((argc == 0) && (read_null_byte == 0)) 
   {
      error = print_acl_from_stdin(type, write_null_byte, not_follow_symlink, verbose);
      return(error ? 1 : 0);
   }

   if ((argc == 0) && (read_null_byte == 1)) 
   {
      error = print_acl_from_stdin_null(type, write_null_byte, not_follow_symlink, verbose);
      return(error ? 1 : 0);
   }


   for (i = 0; i < argc; i++) 
   {

      if (!strcmp(argv[i], "-"))       /* all piped args (on the command line) will get processed in one go */
      {  

         if (read_null_byte == 1)
            print_acl_from_stdin_null(type, write_null_byte, not_follow_symlink, verbose);
         else
            print_acl_from_stdin(type, write_null_byte, not_follow_symlink, verbose);

      }else{

         struct stat sp;

         if (not_follow_symlink == 1)
            error = lstat(argv[i], &sp);
         else
            error = stat(argv[i], &sp);

         if (error != 0) 
         {
            warn("%s", argv[i]);
            return(-1);
         }

         acl_t acl = NULL;

         if (not_follow_symlink == 1)
            acl = acl_get_link_np(argv[i], type);
         else
            acl = acl_get_file(argv[i], type);

         if (acl == NULL)
         {
            fprintf(stderr,"No ACL: %s\n", argv[i]);
            acl_free(acl);
            continue;
         }

         if (write_null_byte == 1)
         {
            if (verbose == 1) {
               printf("file: %s%c", argv[i], 0);
               printf("user: %i %s\n"
                      "goup: %i %s\n"
                      "perms: %o\n"
                      , 
                      sp.st_uid, getuname(sp.st_uid),
                      sp.st_gid, getgname(sp.st_gid),
                      sp.st_mode
               );
            }else{
               printf("%s%c", argv[i], 0);
            }
            printacl(acl, S_ISDIR(sp.st_mode), verbose);    
            putchar(0);
         }else{
            if (verbose == 1)
            {
               count == 0 ? ++count : putchar('\n');
               printf("file: %s\n"
                      "user: %i %s\n"
                      "goup: %i %s\n"
                      "perms: %o\n"
                      , 
                      argv[i],
                      sp.st_uid, getuname(sp.st_uid),
                      sp.st_gid, getgname(sp.st_gid),
                      sp.st_mode
               );
               printacl(acl, S_ISDIR(sp.st_mode), verbose);
            }else{
               count == 0 ? ++count : putchar('\n');
               printf("%s\n", argv[i]);
               printacl(acl, S_ISDIR(sp.st_mode), verbose);   
            }
         }

         acl_free(acl);

      } /* if */

   } /* for */

   return(0);

}
    
