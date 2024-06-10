package CustomSpamDetectorVT;

use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use LWP::UserAgent;
use JSON;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my ($class, $mailsa) = @_;
    my $self = $class->SUPER::new($mailsa);
    bless $self, $class;
    $self->register_eval_rule("check_for_malicious_url_in_body");
    return $self;
}

sub check_for_malicious_url_in_body {
    my ($self, $permsgstatus) = @_;

    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        while ($line =~ m{\bhttps?://[^\s<>"']+\b}gi) {
            my $url = $&;
            if (check_url_with_virustotal($url)) {
                $permsgstatus->test_log("Detected a malicious URL in the email body: $url");
                return 1;
            }
        }
    }
    return 0;
}

sub check_url_with_virustotal {
    my ($url) = @_;

    my $apikey = 'Virus total API'; 
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

        return $malicious_count;
    } else {
        warn "Error: " . $response->status_line . "\n";
        return 0;
    }
}

1;