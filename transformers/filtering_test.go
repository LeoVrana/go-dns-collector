package transformers

import (
	"testing"
  "time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

const (
	TEST_URL1 = "mail.google.com"
	TEST_URL2 = "test.github.com"
	TEST_URL3 = "test.icann.org"
)

func TestFilteringQR(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.LogQueries = false
	config.Filtering.LogReplies = false

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	if !filtering.CheckIfDrop(&dm) {
		t.Errorf("dns query should be ignored")
	}

	dm.DNS.Type = dnsutils.DnsReply
	if !filtering.CheckIfDrop(&dm) {
		t.Errorf("dns reply should be ignored")
	}

}

func TestFilteringByRcodeNOERROR(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.DropRcodes = []string{"NOERROR"}

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped")
	}

}

func TestFilteringByRcodeEmpty(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.DropRcodes = []string{}

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByQueryIp(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.DropQueryIpFile = "../testsdata/filtering_queryip.txt"
	config.Filtering.KeepQueryIpFile = "../testsdata/filtering_queryip_keep.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.NetworkInfo.QueryIp = "192.168.0.1"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.168.1.15"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.168.1.10" // Both in drop and keep, so keep
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.0.2.3" // dropped by subnet
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.0.2.1" // dropped by subnet, but explicitly in keep
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

}

func TestFilteringByFqdn(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.DropFqdnFile = "../testsdata/filtering_fqdn.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "www.microsoft.com"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
  
  dm.DNS.Qname = "github.com"
  if filtering.CheckIfDrop(&dm) == true {
    // subdomain is in list, not the domain
    t.Errorf("dns query should not be dropped!")
  }
}

func TestFilteringByDomainRegex(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = TEST_URL2
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomain(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	// file contains google.fr, test.github.com
	config.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = TEST_URL2
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "google.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomainRegex(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	/* file contains:
	(mail|sheets).google.com$
	test.github.com$
	.+.google.com$
	*/
	config.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains_regex.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.google.com.ru"
	if filtering.CheckIfDrop(&dm) == false {

		// If this passes then these are not terminated.
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = TEST_URL2
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.github.com.malware.ru"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDownsample(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.Downsample = 2

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")
	dm := dnsutils.GetFakeDnsMessage()

	// filtering.downsampleCount
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! downsampled should exclude first hit.")
	}

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampled one record and then should include the next if downsample rate is 2")
	}

	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! downsampled should exclude first hit.")
	}

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampled one record and then should include the next if downsample rate is 2")
	}

	// test for default behavior when downsample is set to 0
	config.Filtering.Downsample = 0
	filtering = NewFilteringProcessor(config, logger.New(false), "test")

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampling rate is set to 0 and should not downsample.")
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampling rate is set to 0 and should not downsample.")
	}

}

func TestFilteringMultipleFilters(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"
	config.Filtering.DropQueryIpFile = "../testsdata/filtering_queryip.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = TEST_URL2
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.168.1.15"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.0.2.3" // dropped by subnet
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByKeepFqdnInclSubs(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	// file contains google.fr, test.github.com
	config.Filtering.KeepFqdnInclSubsFile = "../testsdata/filtering_keep_domains.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "foo.bar." + TEST_URL3
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "foo.bar.google.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByDropFqdnInclSubs(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	// file contains google.com, icann.org
	config.Filtering.DropFqdnInclSubsFile = "../testsdata/filtering_drop_domains.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1 // mail.google.com
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "foo.bar." + TEST_URL3 // test.icann.org
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should not be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "foo.bar.google.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! Domain: %s", dm.DNS.Qname)
	}
}

func TestBenchmarkFqdnInclSubs(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	// file contains google.com, icann.org
	config.Filtering.DropFqdnInclSubsFile = "../testsdata/filtering_drop_domains.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()

  dm.DNS.Qname = TEST_URL1 // mail.google.com
  // drops
  drops_start := time.Now()
  for i := 1; i <= 10000; i++ {
    filtering.CheckIfDrop(&dm)
  }
  t.Logf("Time to check 10,000 drop domains InclSubs: %v", time.Since(drops_start))
  
  // keeps
  dm.DNS.Qname = "example.com"
  keeps_start := time.Now()
  for i := 1; i <= 10000; i++ {
    filtering.CheckIfDrop(&dm)
  }  
  t.Logf("Time to check 10,000 keep domains InclSubs: %v", time.Since(keeps_start))

}

func TestBenchmarkFqdn(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	// file contains google.com, icann.org
	config.Filtering.DropFqdnFile = "../testsdata/filtering_drop_domains.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
  dm.DNS.Qname = "icann.org"
  
  //drops
  drops_start := time.Now()
  for i := 1; i <= 10000; i++ {
    filtering.CheckIfDrop(&dm)
  }
  t.Logf("Time to check 10,000 drop domains Fqdn: %v", time.Since(drops_start))
  
  // keeps
  dm.DNS.Qname = "example.com"
  keeps_start := time.Now()
  for i := 1; i <= 10000; i++ {
    filtering.CheckIfDrop(&dm)
  }
  t.Logf("Time to check 10,000 keep domains Fqdn: %v", time.Since(keeps_start))
}

func TestBenchmarkRegex(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()

	/* file contains 
  (mail|sheets)\.google\.com$
  test\.github\.com$
  .+\.google\.com$
  */

	config.Filtering.DropDomainFile = "../testsdata/filtering_drop_domains_regex.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
  dm.DNS.Qname = "foo.bar.google.com"
  
  //drops
  drops_start := time.Now()
  for i := 1; i <= 10000; i++ {
    filtering.CheckIfDrop(&dm)
  }
  t.Logf("Time to check 10,000 domains against 1,000 regexes (drop): %v", time.Since(drops_start))
  
  // keeps
  dm.DNS.Qname = "example.com"
  keeps_start := time.Now()
  for i := 1; i <= 10000; i++ {
    filtering.CheckIfDrop(&dm)
  }
  t.Logf("Time to check 10,000 domains against 1,000 regexes (keep): %v", time.Since(keeps_start))
}