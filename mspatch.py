#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
mspatch.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2012-03-18 14:19:24'

import os, sys, optparse, popen2, re, shutil
from msPatchInfo import *
import pefile

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

        self._whitelist = [ 'ohotfixr.dll', 'ohotfix.exe', 'ohotfix.ini' ] # TODO more...

    @property
    def tmpdir(self):
        """
        """
        return self._tmpdir

    def getver(self, fname):
        """get file's version
        rip from https://code.google.com/p/ms-patch-tools/source/browse/trunk/msux/dllVers.py
        """
        try:
            pe = pefile.PE( data=open(fname, 'rb').read() )
        except pefile.PEFormatError:
            print '[-] failed to rename, not PE file?'
            return ''

        osMajor = pe.VS_FIXEDFILEINFO.FileVersionMS >> 16
        osMinor = pe.VS_FIXEDFILEINFO.FileVersionMS & 0xffff
        swMajor = pe.VS_FIXEDFILEINFO.FileVersionLS >> 16
        swMinor = pe.VS_FIXEDFILEINFO.FileVersionLS & 0xffff

        return '.%d.%d.%d.%d' % (osMajor, osMinor, swMajor, swMinor)

    def _extract(self, fpatch=None):
        """
        """
        patchee = fpatch if fpatch else self._patchee
        if not patchee:
            raise Exception( 'Patch file missed?' )

        xtracted = []

        # TODO handle msu/msi
        if os.path.basename( patchee ).startswith( 'IE' ):
            cr, cw, ce = popen2.popen3( patchee + " /x:" + self._tmpdir + " /quiet" )
            if ce.read() != "":
                print '[-] failed to extract...(%s)' % patchee
            else:
                for root, dirs, fnames in os.walk( self._tmpdir ):
                    for fname in fnames:
                        if fname.endswith( ('.dll', '.exe', '.ocx') ): # FIXME more?
                            xtracted.append( os.path.join( root, fname ) )

            return xtracted

        elif patchee.endswith( '.exe' ) or patchee.endswith( '.msp' ) or '_CAB_' in patchee:
            cr, cw, ce = popen2.popen3( '7z l ' + patchee )
            tmp = cr.readlines()

            total = len(tmp)
            for i in xrange( total-2, -1, -1 ):

                line = tmp[i].strip()

                if 'Date      Time    Attr         Size   Compressed  Name' in line:
                    break

                pmt = line.split(' ')
                wnt = pmt[-1]
                if wnt not in self._whitelist and '---' not in wnt:
                    if total < 100:
                        xtracted.append( wnt )
                    else:       # FIXME msp tends to have lots of file
                        if '_CAB_' in wnt:
                            xtracted.append( wnt )

            # extract with 7z.exe
            if len(xtracted) != 0:
                popen2.popen3( '7z x -o%s %s %s' % ( self._tmpdir, patchee, ' '.join(xtracted) ) )

            for x in xtracted:
                ftmp = os.path.join(self._tmpdir, x)
                if x.endswith('.msp'):
                    xtracted.remove(x)
                    xtracted.extend( self._extract( ftmp ) )
                    os.unlink( ftmp )
                elif '_CAB_' in x:
                    xtracted.remove(x)
                    xtracted.extend( self._extract( ftmp ) )
                    os.unlink( ftmp )

        else:
            print '---] not implemented yet...(%s)' % patchee

        return xtracted

    def extract(self, fpatch=None):
        """
        """
        xtracted = self._extract(fpatch)
        if len(xtracted) != 0:
            for x in xtracted:
                # rename with PE version
                fname = os.path.join( self._tmpdir, x ) if self._tmpdir not in x else x
                fname = os.path.abspath( fname )
                ver = self.getver( fname )
                if ver == '': continue
                fulln, fext = os.path.splitext(fname)
                nfname = fulln + ver  + fext
                try:
                    shutil.move( fname, nfname )
                except:
                    print '[-] failed to rename? (%s)' % fname

        return xtracted

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

    def get_patch(self, family, direktory, extract_p=False, matcher=''):
        """
        """
        link = 'http://www.microsoft.com/downloads/en/confirmation.aspx?familyid=' + family + '&displayLang=en'

        if not os.path.isdir( direktory ):
            os.makedirs( direktory )

        self.makeSoup( link )

        downloads = list( set( [ x.url for x in self.BR.links( text_regex='Click here' )] ) )

        for link in downloads:
            if matcher != '' and ',' in matcher and matcher.lower().split(',')[1] not in link.lower():
                continue
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
                        xes = ex.extract( fn )
                        if len(xes) != 0:
                            print '---[Extracted in (%s)' % ex.tmpdir
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
            if ( opts.match and opts.match.lower().split(',')[0] not in familyid[0].lower() ):
                continue

            print '---[Target (%s)' % (familyid[0])
            mspatch.get_patch( familyid[1], opts.output, opts.extract, opts.match )

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
                    if ( opts.match and opts.match.lower().split(',')[0] not in familyid[0].lower() ):
                        continue

                    print '---[Target (%s)' % (familyid[0])
                    mspatch.get_patch( familyid[1], os.path.join(opts.output, prevbulletin), opts.extract, opts.match )

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
