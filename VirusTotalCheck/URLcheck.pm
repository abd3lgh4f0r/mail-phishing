#!/usr/bin/perl

use strict;
use warnings;
use LWP::UserAgent;
use JSON;

sub check_url_with_virustotal {
    my ($url) = @_;

    my $apikey = '' # Replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual API key
    my $ua = LWP::UserAgent->new;
    my $endpoint = 'https://www.virustotal.com/vtapi/v2/url/report';

    my $request = HTTP::Request->new(POST => $endpoint);
    $request->content_type('application/x-www-form-urlencoded');
    $request->content("apikey=$apikey&resource=$url");

    my $response = $ua->request($request);

    if ($response->is_success) {
        my $result = decode_json($response->decoded_content);

        # Count the occurrences of "malicious site" and "phishing site"
        my $malicious_count = 0;
        foreach my $scan (values %{ $result->{'scans'} }) {
            if ($scan->{'result'} eq 'malicious site' || $scan->{'result'} eq 'phishing site') {
                $malicious_count++;
            }
        }

        # Construct and return the report
        my $report = {
            url => $url,
            scan_date => $result->{'scan_date'},
            positives => $result->{'positives'},
            total => $result->{'total'},
            scan_result => $result->{'positives'} > 0 ? "Malicious" : "Clean",
            malicious_count => $malicious_count
        };
        return $report;
    } else {
        die "Error: " . $response->status_line . "\n";
    }
}

# Example usage
my $url = 'http://google.com';
my $report = check_url_with_virustotal($url);
print "Malicious Count: $report->{malicious_count}\n";
