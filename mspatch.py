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
import popen2

class PatchExtracter():
    """klass of PatchExtracter
    """

    def __init__(self, fpatch=None, tmpdir='extracted'):
        """
        """
        self._patchee = fpatch
        self._tmpdir  = tmpdir
        if not os.path.isdir( tmpdir ):
            os.makedirs( tmpdir )

    @property
    def tmpdir(self):
        """
        """
        return self._tmpdir

    def extract(self, fpatch=None):
        """
        """
        patchee = fpatch if fpatch else self._patchee
        if not patchee:
            raise Exception( 'Patch file missed?' )

        # TODO handle msu/msp/msi
        if patchee[-4:] == '.exe':
            popen2.popen2( patchee + " /x:" + self._tmpdir + " /quiet" )
            return True

        return False

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

    def getBulletinFileInfo(self, year, num):

        print "-[Retrieving file information for bulletin MS%.2d-%.3d" % (year, num)

        # if year > 11:           # FIXME
        #     url = 'http://technet.microsoft.com/security/bulletin/MS%.2d-%.3d' % (year, num)
        # else:
        #     url = 'http://www.microsoft.com/technet/security/Bulletin/MS%.2d-%.3d.mspx' % (year, num)
        url = 'http://technet.microsoft.com/en-us/security/bulletin/ms%.2d-%.3d' % (year, num)

        print "--[Retrieving %s" % (url)

        soup = self.makeSoup(url)

        prevbulletins = ', '.join( self.prevbulletins )
        if prevbulletins:
            print '--[Replaced Bulletins (%s)' % (prevbulletins)

        if year > 8 or (year == 8 and num >= 18):
            return self.getNewFileInfo(soup, year, num)
        else:
            return self.getOldFileInfo(soup, year, num)

    def query_bulletin(self, year, num):

        print "-[Retrieving file information for bulletin MS%.2d-%.3d" % (year, num)

        # if year > 11:           # FIXME
        #     url = 'http://technet.microsoft.com/security/bulletin/MS%.2d-%.3d' % (year, num)
        # else:
        #     url = 'http://www.microsoft.com/technet/security/Bulletin/MS%.2d-%.3d.mspx' % (year, num)
        url = 'http://technet.microsoft.com/en-us/security/bulletin/ms%.2d-%.3d' % (year, num)

        print "--[Retrieving %s" % (url)

        self.soup = self.makeSoup(url)

        prevbulletins = ', '.join( self.prevbulletins )
        if prevbulletins:
            print '--[Replaced Bulletins (%s)' % (prevbulletins)

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
            # skip Windows Installer's familyid
            if fid in ['5A58B56F-60B6-4412-95B9-54D056D6F9F4', '889482FC-5F56-4A38-B838-DE776FD4138C', ]:
                continue
            yield txt, fid

    @property
    def prevbulletins(self):
        """a generator of 'Bulletins Replaced by this Update'
        """
        tmp = [ x.text for x in self.BR.links( url_regex='go\.microsoft', text_regex='MS\d+\-' ) ]
        tmp = list(set(tmp))    # remove duplicaitons
        for x in tmp:
            yield x

    def get_patch(self, family, direktory, extract_p=False):
        """
        """
        link = 'http://www.microsoft.com/downloads/en/confirmation.aspx?familyid=' + family + '&displayLang=en'

        if not os.path.isdir( direktory ):
            os.makedirs( direktory )

        self.makeSoup( link )

        downloads = [ x for x in self.BR.links( text_regex='Start download' )]

        for x in downloads:
            link = x.url
            print '---[Downloading %s' % (link)
            try:
                rc = self.BR.open( link )
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
                        if int(size) == os.stat( fn )[6]:
                            raise Exception( "differ url, same file tho?" )
                        else:
                            tmpname = (tmpname[::-1] + '-' + str(i))[::-1]
                    i += 1
                data = rc.get_data()
            except Exception, e:
                print '---[...(%s)' % (str(e))
                continue

            if data and len(data) > 0:
                with open( fn, 'wb' ) as fh:
                    fh.write( data )
                print '---[%s saved...' % (fn)

                if extract_p:
                    ex = PatchExtracter( tmpdir=os.path.join(direktory, "extracted", tmpname[:-4]) )
                    try:
                        if ex.extract( fn ):
                            print '---[Extracted in (%s)' % (ex.tmpdir)
                    except Exception, e:
                        print str(e)

def main():
    """TODO
    """
    opt = optparse.OptionParser( usage="usage: %prog [options]", version="%prot " + __version__ )
    opt.add_option( "-y", "--year", help="year of bulletin" )
    opt.add_option( "-n", "--num", help="number string of bulletin" )
    opt.add_option( "-d", "--download", help="flag as download action", action="store_true", default=False )
    opt.add_option( "-o", "--output", help="output directory", default="patches" )
    opt.add_option( "-l", "--list", help="list familyids", action="store_true", default=False )
    opt.add_option( "-m", "--match", help="string to match target" )
    opt.add_option( "-e", "--extract", help="flag as extract action", action="store_true", default=False )
    opt.add_option( "-f", "--follow", help="follow replaced bulletins", action="store_true", default=False )

    (opts, args) = opt.parse_args()

    if not opts.year or not opts.num:
        opt.print_help()
        sys.exit(-1)

    mspatch = MsPatchWrapper()

    if opts.download:

        mspatch.query_bulletin( int(opts.year), int(opts.num) )

        prevbulletins = [ x for x in mspatch.prevbulletins ]

        for familyid in mspatch.familyids:
            if ( opts.match and opts.match.lower() not in familyid[0].lower() ):
                continue

            print '---[Target (%s)' % (familyid[0])
            mspatch.get_patch( familyid[1], opts.output, opts.extract )

        if opts.follow:

            # FIXME follow once?
            for prevbulletin in prevbulletins:
                m = re.match( 'MS((?P<year>\d+))-((?P<num>\S+))', prevbulletin )
                if not m:
                    print '----[wtf?? (%s)' % (prevbulletin)
                    continue

                print '----[Following bulletin (%s)' % (prevbulletin)

                mspatch.query_bulletin( int(m.group('year')), int(m.group('num')) )

                for familyid in mspatch.familyids:
                    if ( opts.match and opts.match.lower() not in familyid[0].lower() ):
                        continue

                    print '---[Target (%s)' % (familyid[0])
                    mspatch.get_patch( familyid[1], os.path.join(opts.output, prevbulletin), opts.extract )

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
