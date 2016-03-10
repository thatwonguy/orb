#!/usr/bin/env python 
# -*- coding: utf-8 -*-"
"""
This file is part of the orb project, http://orb.03c8.net

Orb - 2016 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with RedSquat; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import optparse

class OrbOptions(optparse.OptionParser):
    def __init__(self, *args):
        optparse.OptionParser.__init__(self, 
                           description='\nOrb: footprinting tool - by psy',
                           prog='Orb.py',
                           version='\nVersion: v0.1\n')
        self.add_option("-v", "--verbose", action="store_true", dest="verbose", help="active verbose on requests")
        self.add_option("--check-tor", action="store_true", dest="checktor", help="check to see if Tor is used properly")
        self.add_option("--gui", action="store_true", dest="gui", help="run GUI (Orb Web Interface)")
        self.add_option("--spell", action="store", dest="target", help="start footprinting on this target")

    def get_options(self, user_args=None):
        (options, args) = self.parse_args(user_args)
        if (not options.checktor and not options.target and not options.gui):
            print '='*75, "\n"
            print "  _|_|              _|        "
            print "_|    _|  _|  _|_|  _|_|_|    "
            print "_|    _|  _|_|      _|    _|  "
            print "_|    _|  _|        _|    _|  "
            print "  _|_|    _|        _|_|_|    "
            print self.description, "\n"
            print '='*75, "\n"
            return False
        return options
