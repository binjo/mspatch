#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
mspatch.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2012-03-18 14:19:24'

import os, sys
import optparse
from msPatchInfo import *

class MsPatchWrapper(msPatchFileInfo):
    """wrapper klass of mspatchfileinfo
    """

    def __init__(self, proxy=None):
        """
        """
        msPatchFileInfo.__init__(self)
        self.BR.set_handle_robots(False) # don't follow rule of robots.txt
        if proxy is not None:
            self.BR.set_proxies( proxy ) # proxy = {'http':'xxxx:port'}

        self.soup = None

    def query_bulletin(self, year, num):

        print "-[Retrieving file information for bulletin MS%.2d-%.3d" % (year, num)

        # if year > 11:           # FIXME
        #     url = 'http://technet.microsoft.com/security/bulletin/MS%.2d-%.3d' % (year, num)
        # else:
        #     url = 'http://www.microsoft.com/technet/security/Bulletin/MS%.2d-%.3d.mspx' % (year, num)
        url = 'http://technet.microsoft.com/en-us/security/bulletin/ms%.2d-%.3d' % (year, num)

        print "--[Retrieving %s" % (url)

        self.soup = self.makeSoup(url)

    @property
    def familyids(self):
        """
        """
        for x in self.BR.links( url_regex='details\.aspx\?familyid=' ):
            txt = x.text
            url = x.url
            fid = url[url.find('=')+1:]
            if fid.find( '&' ) != -1:
                fid = fid[:fid.find('&')]
            yield txt, fid

    @property
    def prevbulletins(self):
        """a generator of 'Bulletins Replaced by this Update'
        """
        for x in self.BR.links( url_regex='go\.microsoft', text_regex='MS\d+\-' ):
            yield x.text

    def get_patch(self, family, direktory):
        """
        """
        link = 'http://www.microsoft.com/downloads/en/confirmation.aspx?familyid=' + family + '&displayLang=en'

        self.makeSoup( link )

        downloads = [ x for x in self.BR.links( text_regex='Start download' )]

        for x in downloads:
            link = x.url
            print '---[Downloading %s' % (link)
            try:
                rc = self.BR.open( link )
                data = rc.get_data()
                size = rc.info().getheader( 'content-length' )
                # awkward fix of duplicate patch file name
                fn = tmpname = link[link.rfind('/')+1:]
                i = 1
                while True:
                    fn = os.path.join( direktory, tmpname )
                    if not os.path.isfile( fn ):
                        break
                    else:
                        # same file name exists
                        if size == os.stat( fn )[6]:
                            raise Exception, "differ url, same file tho?"
                        else:
                            tmpname = (tmpname[::-1] + '-' + str(i))[::-1]
                    i += 1
            except Exception, e:
                print '---[...(%s)' % (str(e))
                continue

            if data and len(data) > 0:
                with open( fn, 'wb' ) as fh:
                    fh.write( data )
                print '---[%s saved...' % (fn)

def main():
    """TODO
    """
    opt = optparse.OptionParser( usage="usage: %prog [options]", version="%prot " + __version__ )
    opt.add_option( "-y", "--year", help="year of bulletin" )
    opt.add_option( "-n", "--num", help="number string of bulletin" )
    opt.add_option( "-a", "--all", help="set flag to downthemall", action="store_true", default=False )
    opt.add_option( "-d", "--download", help="flag as download action", action="store_true", default=False )
    opt.add_option( "-o", "--output", help="output directory", default="patches" )
    opt.add_option( "-l", "--list", help="list familyids", action="store_true", default=False )
    opt.add_option( "-m", "--match", help="string to match target" )

    (opts, args) = opt.parse_args()

    if not opts.year or not opts.num:
        opt.print_help()
        sys.exit(-1)

    mspatch = MsPatchWrapper()

    if not os.path.isdir( opts.output ):
        os.mkdir( opts.output )

    if opts.download:

        mspatch.query_bulletin( int(opts.year), int(opts.num) )

        if opts.match:
            for familyid in mspatch.familyids:
                if opts.match.lower() in familyid[0].lower():
                    print '---[Target (%s)' % (familyid[0])
                    mspatch.get_patch( familyid[1], opts.output )
        elif opts.all:
            for familyid in mspatch.familyids:
                print '---[Target (%s)' % (familyid[0])
                mspatch.get_patch( familyid[1], opts.output )

    elif opts.list:

        mspatch.query_bulletin( int(opts.year), int(opts.num) )

        for (target, phamilyid) in mspatch.familyids:
            print '|%-40s | %-40s' % (phamilyid, target)

    else:

        results = mspatch.getBulletinFileInfo( int(opts.year), int(opts.num) )
        res = mspatch.generateOutput( results )
        res = ''.join(filter(lambda x:x in string.printable, res))
        print res

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
