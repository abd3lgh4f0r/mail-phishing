package URL_Phishing;


use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my ($class, $mailsa) = @_;
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);
    $self->register_eval_rule('check_ip_address');
    $self->register_eval_rule('check_long_url');
    $self->register_eval_rule('check_short_url');
    $self->register_eval_rule('check_at_symbol');
    $self->register_eval_rule('check_double_slash');
    $self->register_eval_rule('check_dash_in_domain');
    $self->register_eval_rule('check_multiple_subdomains');
    return $self;
}

sub check_ip_address {
    my ($self, $permsgstatus) = @_;
    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        if ($line =~ m{\bhttp://\d+\.\d+\.\d+\.\d+\b}i) {
            $permsgstatus->test_log("Detected an IP address in the URL.");
            return 1;
        }
    }
    return 0;
}


sub check_short_url {
    my ($self, $permsgstatus) = @_;
    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        if ($line =~ m{\bhttp://(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|buff\.ly|ow\.ly)/\b}) {
            $permsgstatus->test_log("Detected a shortened URL.");
            return 1;
        }
    }
    return 0;
}

sub check_at_symbol {
    my ($self, $permsgstatus) = @_;
    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        if ($line =~ m{@}) {
            $permsgstatus->test_log("Detected an @ symbol in the URL.");
            return 1;
        }
    }
    return 0;
}

sub check_double_slash {
    my ($self, $permsgstatus) = @_;
    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        if ($line =~ m{\bhttp://.*//\b}i) {
            $permsgstatus->test_log("Detected a double slash in the URL.");
            return 1;
        }
    }
    return 0;
}

sub check_dash_in_domain {
    my ($self, $permsgstatus) = @_;
    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        if ($line =~ m{\bhttp://.*-.*\.\b}) {
            $permsgstatus->test_log("Detected a dash in the domain.");
            return 1;
        }
    }
    return 0;
}

sub check_multiple_subdomains {
    my ($self, $permsgstatus) = @_;
    my $body_text_array = $permsgstatus->get_decoded_body_text_array();
    foreach my $line (@$body_text_array) {
        if ($line =~ m{\bhttp://(?:[\w\-]+\.)+[\w\-]+\b} && $line !~ m{\b(?:\d{1,3}\.){3}\d{1,3}\b}) {
            $permsgstatus->test_log("Detected multiple subdomains in the URL.");
            return 1;
        }
    }
    return 0;
}


1;
