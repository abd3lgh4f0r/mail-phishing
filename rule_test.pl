#open spam assassin file : /opt/zimbra/data/spamassassin/localrules
#add this rule :
# Custom Rule: Detects "free money" in the subject line
header CUSTOM_SUBJECT_FREE_MONEY Subject =~ /free money/i
score CUSTOM_SUBJECT_FREE_MONEY 5.0
describe CUSTOM_SUBJECT_FREE_MONEY Subject contains 'free money'
#then restart spamassassin
#sudo systemctl restart 