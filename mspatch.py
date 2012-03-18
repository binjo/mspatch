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
            yield txt, fid

    def get_patch(self, family, direktory):
        """
        """
        link = 'http://www.microsoft.com/downloads/en/confirmation.aspx?familyid=' + family + '&displayLang=en'

        self.makeSoup( link )

        downloads = [ x for x in self.BR.links( text_regex='Start download' )]

        for x in downloads:
            link = x.url
            fn = os.path.join( direktory, link[link.rfind('/')+1:] )
            print '---[Downloading %s -> (%s)' % (link, fn)
            try:
                data = self.BR.open( link ).get_data()
            except Exception, e:
                print '---[Failed...(%s)' % (str(e))
                continue

            if data and len(data) > 0:
                with open( fn, 'wb' ) as fh:
                    fh.write( data )
                print '---[done...'

def main():
    """TODO
    """
    opt = optparse.OptionParser( usage="usage: %prog [options]", version="%prot " + __version__ )
    opt.add_option( "-y", "--year", help="year of bulletin" )
    opt.add_option( "-n", "--num", help="number string of bulletin" )
    opt.add_option( "-f", "--familyid", help="familyid of certain target" )
    opt.add_option( "-a", "--all", help="set flag to downthemall", action="store_true", default=False )
    opt.add_option( "-d", "--download", help="flag as download action", action="store_true", default=False )
    opt.add_option( "-o", "--output", help="output directory", default="patches" )
    opt.add_option( "-l", "--list", help="list familyids", action="store_true", default=False )

    (opts, args) = opt.parse_args()

    if not opts.year or not opts.num:
        opt.print_help()
        sys.exit(-1)

    mspatch = MsPatchWrapper()

    if not os.path.isdir( opts.output ):
        os.mkdir( opts.output )

    if opts.download:

        mspatch.query_bulletin( int(opts.year), int(opts.num) )

        if opts.familyid:
            mspatch.get_patch( opts.familyid, opts.output )
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
