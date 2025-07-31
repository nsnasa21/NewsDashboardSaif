import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import re
from collections import Counter
import numpy as np
from textblob import TextBlob
import time
from urllib.parse import urlparse
import validators
import io

# Page configuration
st.set_page_config(
    page_title="News Aggregation Tool",
    page_icon="📰",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f4e79;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f4e79;
    }
    .news-card {
        background-color: #000000;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #e0e0e0;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .suspicious-card {
        background-color: #fff5f5;
        border: 1px solid #feb2b2;
        border-left: 4px solid #f56565;
    }
    .topic-tag {
        background-color: #4299e1;
        color: white;
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
        font-size: 0.8rem;
        margin-right: 0.5rem;
        display: inline-block;
        margin-bottom: 0.3rem;
    }
    .category-header {
        background-color: #2d3748;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 0.3rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .verification-badge {
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
        font-size: 0.75rem;
        font-weight: bold;
        margin-left: 0.5rem;
    }
    .verified-badge {
        background-color: #c6f6d5;
        color: #2f855a;
    }
    .suspicious-badge {
        background-color: #fed7d7;
        color: #c53030;
    }
    .rejected-badge {
        background-color: #e2e8f0;
        color: #4a5568;
    }
</style>
""", unsafe_allow_html=True)

class NewsAggregationDashboard:
    def __init__(self):
        # Initialize from session state or defaults
        if 'api_keys' not in st.session_state:
            st.session_state.api_keys = {
                'newsapi': '',
                'newsdata': '',
                'gnews': ''
            }
        
        if 'news_categories' not in st.session_state:
            st.session_state.news_categories = {
                'Fraud Detection': {
                    'SIM Swapping': ['sim swap', 'sim swapping', 'sim hijack', 'sim card fraud', 'SIM jacking', 'number porting scam', 'mobile number takeover', '2FA bypass fraud', 'OTP interception'],
                    'Smishing': ['smishing', 'sms phishing', 'text scam', 'sms fraud'],
                    'Vishing': ['vishing', 'voice phishing', 'phone scam', 'robocall fraud'],
                    'Caller ID Spoofing': ['caller id spoofing', 'number spoofing', 'call spoofing'],
                    'Premium Rate Fraud': ['premium rate', 'premium sms', 'expensive calls'],
                    'Telecom Infrastructure Fraud': ['telecom infrastructure', 'network fraud', 'billing fraud'],
                    'Wangiri Fraud': ['wangiri', 'one ring scam', 'one ring fraud', 'missed call scam', 'missed call fraud', 'international callback scam', 'international callback fraud'],
                    'International Revenue Share Fraud': ['irsf', 'international revenue sharing', 'revenue share fraud', 'SMS Pumping'],
                    'Subscription Fraud': ['subscription fraud', 'fake subscription', 'unwanted subscription', 'telecom subscription fraud', 'fake id telecom', 'synthetic id fraud telecom', 'device jailbreak resale', 'unpaid service fraud'],
                    'Toll Fraud': ['toll fraud', 'toll scam', 'pbx hacking', 'phone system fraud', 'VoIP exploitation', 'phone system compromise', 'unauthorized call routing', 'telecom system breach'],
                    'SIMBox Fraud': ['SIMBox', 'SIM Box', 'SIM Box Fraud'],
                    'VoIP Fraud': ['VoIP Fraud', 'Voice over IP Fraud', 'VoIP Scam', 'Voice over IP Scam'],
                    'Traffic Pumping': ['traffic pumping', 'access simulation', 'interconnection fee', 'artificially inflated traffic', 'AIT', 'artificial traffic', 'interconnection fee abuse'],
                    'Deposit Fraud': ['telecom deposit fraud', 'prepaid sim fraud', 'stolen credit card telecom', 'device fraud', 'online store fraud telecom'],
                    'Account Takeover Fraud': ['telecom account takeover', 'ATO fraud telecom', 'account compromise telecom', 'unauthorized account access', 'stolen credentials telecom'],
                    'Cellphone Cloning': ['cellphone cloning fraud', 'mobile subscriber fraud', 'telecom identity duplication', 'unauthorized cellular use'],
                    'Cramming': ['phone bill cramming', 'unauthorized phone charges', 'deceptive billing telecom', 'misleading phone bill'],
                    'Slamming': ['phone slamming', 'unauthorized carrier switch', 'telecom service hijacking', 'illegal phone service change'],
                    'Voicemail Hacking Scam': ['voicemail hacking', 'collect call scam voicemail', 'international call fraud voicemail', 'default password exploit telecom'],
                    'Robocall Scams': ['robocall scam', 'imposter scam', 'fake police call'],
                    'Collect Call Scam': ['809 scam', 'collect call scam', 'international call back fraud', 'unfamiliar area code scam'],
                    'Phishing': ['phishing scam', 'email phishing', 'malicious link scam', 'credential harvesting', 'fake login page', 'spoofed email', 'AI phishing'],
                    'Imposter Scams': ['imposter scam', 'government imposter fraud', 'IRS scam call', 'tech support scam', 'Microsoft scam', 'anti-virus scam', 'charity fraud call', 'family emergency scam', 'grandparent scam', 'utility scam call', 'veteran benefits fraud', 'DHS scam', 'Social Security scam', 'Europol imposter scam'],
                    'Romance and Catfishing Scams': ['romance scam', 'catfishing fraud', 'online dating scam', 'fake identity dating', 'deepfake romance scam'],
                    'Advance Fee Scams': ['advance fee scam', 'loan scam upfront fee', 'lottery prize scam', 'sweepstakes fraud', 'government grant scam', 'inheritance scam', 'work from home scam fee', 'wire transfer scam', 'gift card scam payment', 'cryptocurrency scam payment'],
                    'Online Shopping and Holiday Frauds': ['fake online store', 'counterfeit goods scam', 'holiday fraud', 'fake accommodation scam', 'AI generated listing scam', 'online marketplace fraud', 'triangulation fraud'],
                    'Employment and Business Opportunity Scams': ['employment scam', 'job offer fraud', 'work from home scam', 'business opportunity fraud', 'upfront fee job', 'fake check employment', 'overpayment scam job'],
                    'Copycat Websites': ['copycat website scam', 'fake government website', 'bogus customer service number', 'official document fraud online', 'search engine scam'],
                    'Pharming': ['pharming attack', 'website redirection fraud', 'DNS poisoning scam', 'fake banking site redirect'],
                    'Free Trial Scams': ['free trial scam', 'subscription trap fraud', 'unwanted charges trial', 'credit card trial scam'],
                    'Mandate Fraud': ['mandate fraud', 'invoice scam email', 'business email compromise BEC', 'payment redirection fraud', 'supplier invoice scam'],
                    'Cryptocurrency Scams': ['cryptocurrency scam', 'crypto investment fraud', 'fake crypto scheme', 'bitcoin scam', 'altcoin fraud'],
                    'General Holiday Scams': ['holiday scam', 'holiday fraud', 'Eid fraud', 'Eid scam', 'Christmas scam', 'Black Friday fraud', 'seasonal scam', 'fake charity holiday'],
                    'Malware Attacks': ['malware attack', 'ransomware attack', 'data encryption scam', 'keylogger fraud', 'trojan data theft', 'spyware data breach', 'malicious software data', 'AI malware'],
                    'Social Engineering': ['social engineering attack', 'pretexting scam', 'baiting fraud', 'quizzes survey scam', 'psychological manipulation cyber', 'human hacking'],
                    'Software Exploits and Vulnerabilities': ['software exploit', 'vulnerability exploitation', 'unpatched software attack', 'zero-day exploit', 'privilege escalation', 'remote code execution', 'system compromise'],
                    'Insider Threats': ['insider threat', 'employee data theft', 'privileged access abuse', 'data compromise insider', 'disgruntled employee data'],
                    'Payment Card Fraud (Skimming)': ['payment card fraud', 'credit card skimming', 'ATM skimmer', 'POS fraud', 'card data theft'],
                    'Physical Theft (Devices, Documents)': ['physical data theft', 'laptop theft data breach', 'stolen hard drive data', 'document theft sensitive data'],
                    'Unintended Disclosure / Human Error': ['unintended data disclosure', 'human error data breach', 'negligence data leak', 'accidental data exposure', 'misconfigured system data'],
                    'Credential Theft': ['credential theft', 'weak password hack', 'stolen login info', 'dictionary attack', 'brute force attack', 'password compromise', 'account credential theft'],
                    'Eavesdropping': ['network eavesdropping', 'unencrypted traffic interception', 'data sniffing', 'packet capture data theft']
                },
                'Technology': {
                    'Artificial Intelligence': ['artificial intelligence', 'AI', 'machine learning', 'deep learning', 'neural networks'],
                    'Cybersecurity': ['cybersecurity', 'data breach', 'hacking', 'cyber attack', 'malware'],
                    'Cloud Computing': ['cloud computing', 'AWS', 'Azure', 'Google Cloud', 'serverless'],
                    'Blockchain': ['blockchain', 'cryptocurrency', 'bitcoin', 'ethereum', 'web3']
                },
                'Business': {
                    'Mergers & Acquisitions': ['merger', 'acquisition', 'buyout', 'takeover', 'consolidation'],
                    'IPO & Markets': ['IPO', 'initial public offering', 'stock market', 'NYSE', 'NASDAQ'],
                    'Startups': ['startup', 'venture capital', 'funding round', 'unicorn company'],
                    'Economic Indicators': ['GDP', 'inflation', 'unemployment', 'economic growth', 'recession']
                }
            }
        
        self.news_apis = st.session_state.api_keys
        self.news_categories = st.session_state.news_categories
    
    def save_api_keys(self, newsapi_key, newsdata_key, gnews_key):
        """Save API keys to session state"""
        st.session_state.api_keys = {
            'newsapi': newsapi_key,
            'newsdata': newsdata_key,
            'gnews': gnews_key
        }
        self.news_apis = st.session_state.api_keys
    
    def add_category(self, category_name):
        """Add new category"""
        if category_name and category_name not in st.session_state.news_categories:
            st.session_state.news_categories[category_name] = {}
            self.news_categories = st.session_state.news_categories
            return True
        return False
    
    def remove_category(self, category_name):
        """Remove category"""
        if category_name in st.session_state.news_categories:
            del st.session_state.news_categories[category_name]
            self.news_categories = st.session_state.news_categories
            return True
        return False
    
    def add_key_topic(self, category_name, topic_name, keywords):
        """Add new key topic to a category"""
        if category_name in st.session_state.news_categories and topic_name and keywords:
            keyword_list = [kw.strip().lower() for kw in keywords.split(',') if kw.strip()]
            if keyword_list:
                st.session_state.news_categories[category_name][topic_name] = keyword_list
                self.news_categories = st.session_state.news_categories
                return True
        return False
    
    def remove_key_topic(self, category_name, topic_name):
        """Remove key topic from category"""
        if (category_name in st.session_state.news_categories and 
            topic_name in st.session_state.news_categories[category_name]):
            del st.session_state.news_categories[category_name][topic_name]
            self.news_categories = st.session_state.news_categories
            return True
        return False
    
    def fetch_news_from_newsapi(self, query, days=7):
        """Fetch news from NewsAPI"""
        url = "https://newsapi.org/v2/everything"
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        params = {
            'q': query,
            'from': start_date.strftime('%Y-%m-%d'),
            'to': end_date.strftime('%Y-%m-%d'),
            'sortBy': 'publishedAt',
            'language': 'en',
            'apiKey': self.news_apis['newsapi']
        }
        
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json().get('articles', [])
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching from NewsAPI for query '{query}': {e}")
        return []
    
    def fetch_news_from_newsdata(self, query, days=7):
        """Fetch news from NewsData API"""
        url = "https://newsdata.io/api/1/news"
        
        params = {
            'apikey': self.news_apis['newsdata'],
            'q': query,
            'language': 'en'
        }
        
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json().get('results', [])
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching from NewsData for query '{query}': {e}")
        return []
    
    def fetch_news_from_gnews(self, query, days=7):
        """Fetch news from GNews API"""
        url = "https://gnews.io/api/v4/search"
        
        params = {
            'q': query,
            'token': self.news_apis['gnews'],
            'lang': 'en',
            'max': 100
        }
        
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json().get('articles', [])
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching from GNews for query '{query}': {e}")
        return []
    
    def verify_url(self, url):
        """Verify if URL is valid and accessible"""
        if not url or not isinstance(url, str) or url.strip() == '':
            return False, "Empty or invalid URL"
        
        if not validators.url(url):
            return False, "Invalid URL format"
        
        parsed = urlparse(url)
        suspicious_patterns = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'localhost', '127.0.0.1', '.onion']
        
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            return False, "Suspicious URL (shortener or local)"
        
        try:
            # Use a HEAD request for efficiency
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code >= 400:
                return False, f"URL not accessible (Status: {response.status_code})"
            return True, "Valid and accessible URL"
        except requests.exceptions.RequestException:
            return False, "URL verification request failed"
    
    def verify_article_authenticity(self, article):
        """Comprehensive article authenticity verification"""
        authenticity_score = 0
        issues = []
        
        url_valid, url_message = self.verify_url(article.get('url', ''))
        if not url_valid:
            issues.append(f"URL Issue: {url_message}")
        else:
            authenticity_score += 50
        
        title = article.get('title', '').strip()
        if not title or len(title) < 20:
            issues.append("Title is too short or missing")
        else:
            authenticity_score += 20
        
        description = article.get('description', '').strip()
        if not description or len(description) < 30:
            issues.append("Description is too short or missing")
        else:
            authenticity_score += 15
        
        pub_date = article.get('published_at') or article.get('publishedAt')
        if not pub_date:
            issues.append("Missing publication date")
        else:
            authenticity_score += 10
        
        source_info = article.get('source', {})
        if isinstance(source_info, dict) and not source_info.get('name'):
            issues.append("Missing source name")
        else:
            authenticity_score += 5
            
        status = 'rejected'
        if authenticity_score >= 70:
            status = 'verified'
        elif 40 <= authenticity_score < 70:
            status = 'suspicious'
        
        return {'status': status, 'authenticity_score': authenticity_score, 'issues': issues}
    
    def classify_topics(self, text):
        """Classify topics based on managed categories and key topics"""
        text_lower = text.lower()
        detected_topics = {}
        for category, topics in self.news_categories.items():
            category_topics = []
            for topic_name, keywords in topics.items():
                if any(keyword in text_lower for keyword in keywords):
                    category_topics.append(topic_name)
            if category_topics:
                detected_topics[category] = list(set(category_topics))
        return detected_topics
    
    def get_search_queries(self, selected_categories: list):
        """Generate search queries based on user-selected categories."""
        if not selected_categories:
            return []
        
        queries = []
        for category_name in selected_categories:
            if category_name in self.news_categories:
                topics = self.news_categories[category_name]
                for keywords in topics.values():
                    queries.extend(keywords)
        
        return list(set(queries))

    def export_to_csv(self, articles):
        """Export articles to CSV with title, topics, categories, and URL"""
        export_data = []
        for article in articles:
            topics_str = " | ".join([f"{cat}: {', '.join(topics)}" for cat, topics in article['detected_topics'].items()])
            export_data.append({
                'Title': article['title'],
                'Topics': topics_str,
                'URL': article['url'],
                'Source': article['source'],
                'Published Date': article['published_at'],
                'Verification Status': article['verification']['status'],
                'Authenticity Score': article['verification']['authenticity_score']
            })
        df = pd.DataFrame(export_data)
        return df.to_csv(index=False).encode('utf-8')

    def process_news_data(self, all_articles):
        """Process and standardize news data from different APIs"""
        processed_articles = []
        verification_stats = Counter()
        
        for article in all_articles:
            if not article or not article.get('title'):
                continue

            processed_article = {
                'title': article.get('title'),
                'description': article.get('description') or article.get('content', ''),
                'url': article.get('url'),
                'published_at': article.get('publishedAt') or article.get('pubDate'),
                'source': (article.get('source', {}).get('name') if isinstance(article.get('source'), dict) else article.get('source')) or 'Unknown',
                'urlToImage': article.get('urlToImage') or article.get('image_url')
            }

            verification_result = self.verify_article_authenticity(processed_article)
            processed_article['verification'] = verification_result
            verification_stats[verification_result['status']] += 1

            content_for_analysis = f"{processed_article['title']} {processed_article['description']}"
            processed_article['detected_topics'] = self.classify_topics(content_for_analysis)
            processed_article['sentiment'] = TextBlob(content_for_analysis).sentiment.polarity
            
            processed_articles.append(processed_article)
        
        st.session_state.verification_stats = dict(verification_stats)
        return processed_articles

def main():
    st.markdown('<h1 class="main-header">📰 News Aggregation Tool</h1>', unsafe_allow_html=True)
    
    dashboard = NewsAggregationDashboard()
    
    st.sidebar.header("Dashboard Controls")
    
    st.sidebar.subheader("API Configuration")
    newsapi_status = "✅ Configured" if st.session_state.api_keys['newsapi'] else "❌ Not configured"
    newsdata_status = "✅ Configured" if st.session_state.api_keys['newsdata'] else "❌ Not configured"
    gnews_status = "✅ Configured" if st.session_state.api_keys['gnews'] else "❌ Not configured"
    st.sidebar.write(f"NewsAPI: {newsapi_status}")
    st.sidebar.write(f"NewsData API: {newsdata_status}")
    st.sidebar.write(f"GNews API: {gnews_status}")
    
    with st.sidebar.expander("🔑 Manage API Keys"):
        newsapi_key = st.text_input("NewsAPI Key", value=st.session_state.api_keys['newsapi'], type="password")
        newsdata_key = st.text_input("NewsData API Key", value=st.session_state.api_keys['newsdata'], type="password")
        gnews_key = st.text_input("GNews API Key", value=st.session_state.api_keys['gnews'], type="password")
        if st.button("💾 Save API Keys"):
            dashboard.save_api_keys(newsapi_key, newsdata_key, gnews_key)
            st.success("API Keys saved successfully!")
            st.rerun()

    st.sidebar.subheader("🏷️ Categories & Topics")
    with st.sidebar.expander("Manage Categories & Topics"):
        # Add Category
        new_category = st.text_input("New Category Name")
        if st.button("➕ Add Category"):
            if dashboard.add_category(new_category):
                st.success(f"Added category: {new_category}")
                st.rerun()
            else:
                st.error("Category name cannot be empty or already exist.")

        # Add Key Topic
        if list(st.session_state.news_categories.keys()):
            selected_category_for_topic = st.selectbox("Select Category for New Topic", options=list(st.session_state.news_categories.keys()))
            new_topic = st.text_input("New Topic Name")
            new_keywords = st.text_input("Keywords (comma-separated)")
            if st.button("➕ Add Topic"):
                if dashboard.add_key_topic(selected_category_for_topic, new_topic, new_keywords):
                    st.success(f"Added topic '{new_topic}' to {selected_category_for_topic}")
                    st.rerun()
                else:
                    st.error("Topic name and keywords are required.")

        # Display and Remove
        for category_name, topics in list(st.session_state.news_categories.items()):
            st.markdown(f"**📁 {category_name}**")
            if st.button("🗑️", key=f"del_cat_{category_name}", help=f"Delete category {category_name}"):
                dashboard.remove_category(category_name)
                st.rerun()
            for topic_name in list(topics.keys()):
                st.markdown(f"&nbsp;&nbsp;&nbsp;• {topic_name}")
                if st.button("🗑️", key=f"del_topic_{category_name}_{topic_name}", help=f"Delete topic {topic_name}"):
                    dashboard.remove_key_topic(category_name, topic_name)
                    st.rerun()
            st.markdown("---")


    st.sidebar.subheader("Search Parameters")

    # MODIFICATION: Allow user to select categories to search
    all_category_names = list(st.session_state.news_categories.keys())
    selected_search_categories = st.sidebar.multiselect(
        "Choose categories to search",
        options=all_category_names,
        default=all_category_names  # Default to all selected
    )
    
    days_back = st.sidebar.slider("Days to look back", 1, 30, 7)
    
    if st.sidebar.button("🔄 Fetch Latest News", type="primary"):
        # MODIFICATION: Check if categories were selected
        if not selected_search_categories:
            st.error("Please select at least one category to search.")
        else:
            with st.spinner("Fetching news..."):
                all_articles = []
                # MODIFICATION: Get queries only from selected categories
                queries = dashboard.get_search_queries(selected_categories=selected_search_categories)
                
                if not queries:
                    st.error("Selected categories have no keywords. Please add topics and keywords first.")
                    return
                
                queries_to_run = list(set(queries))[:20] # Limit API calls
                progress_bar = st.progress(0)
                
                for i, query in enumerate(queries_to_run):
                    if dashboard.news_apis['newsapi']:
                        all_articles.extend(dashboard.fetch_news_from_newsapi(query, days_back))
                    if dashboard.news_apis['newsdata']:
                        all_articles.extend(dashboard.fetch_news_from_newsdata(query, days_back))
                    if dashboard.news_apis['gnews']:
                        all_articles.extend(dashboard.fetch_news_from_gnews(query, days_back))
                    time.sleep(0.5) # Basic rate-limiting
                    progress_bar.progress((i + 1) / len(queries_to_run))

                if all_articles:
                    processed_articles = dashboard.process_news_data(all_articles)
                    unique_articles = {article['title'].lower(): article for article in processed_articles}.values()
                    st.session_state.articles = sorted(list(unique_articles), key=lambda x: x['published_at'], reverse=True)
                    st.success(f"Fetched and processed {len(st.session_state.articles)} unique articles.")
                else:
                    st.warning("No articles found for the selected categories.")

    if 'articles' in st.session_state and st.session_state.articles:
        articles = st.session_state.articles
        
        st.subheader("📊 Key Metrics")
        stats = st.session_state.get('verification_stats', {})
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Articles", len(articles))
        col2.metric("✅ Verified", stats.get('verified', 0))
        col3.metric("⚠️ Suspicious", stats.get('suspicious', 0))
        col4.metric("❌ Rejected", stats.get('rejected', 0))

        st.download_button(
            label="📥 Download Data as CSV",
            data=dashboard.export_to_csv(articles),
            file_name=f"news_export_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )

        st.header("📰 News Feed")
        col1, col2, col3 = st.columns(3)
        all_display_categories = sorted(list(set(cat for article in articles for cat in article['detected_topics'].keys())))
        selected_display_categories = col1.multiselect("Filter displayed articles by Category", options=all_display_categories)
        selected_status = col2.multiselect("Filter by Status", options=['verified', 'suspicious', 'rejected'], default=['verified', 'suspicious'])
        
        filtered_articles = articles
        if selected_display_categories:
            filtered_articles = [a for a in filtered_articles if any(cat in a['detected_topics'] for cat in selected_display_categories)]
        if selected_status:
            filtered_articles = [a for a in filtered_articles if a['verification']['status'] in selected_status]

        st.write(f"Displaying {len(filtered_articles)} articles.")

        for article in filtered_articles:
            st.markdown("---")
            status = article['verification']['status']
            badge_class = f"{status}-badge"
            st.subheader(article['title'])
            st.markdown(f"**Source:** {article['source']} <span class='verification-badge {badge_class}'>{status.upper()}</span>", unsafe_allow_html=True)
            
            for category, topics in article['detected_topics'].items():
                st.write(f"**{category}:** " + " ".join([f"<span class='topic-tag'>{topic}</span>" for topic in topics]), unsafe_allow_html=True)

            with st.expander("Article Details"):
                if article.get('urlToImage'):
                    st.image(article['urlToImage'])
                st.write(f"**Description:** {article.get('description', 'Not available.')}")
                st.write(f"**URL:** [Link to Article]({article['url']})")
                st.write(f"**Published:** {article.get('published_at', 'Not available.')}")
                st.write(f"**Authenticity Score:** {article['verification']['authenticity_score']}/100")
                if article['verification']['issues']:
                    st.warning(f"**Verification Issues:** {', '.join(article['verification']['issues'])}")

if __name__ == "__main__":
    main()
