import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta
from collections import Counter
from textblob import TextBlob
import time
from urllib.parse import urlparse
import validators
import io
import feedparser

# Page configuration
st.set_page_config(
    page_title="Universal Content Aggregation Dashboard",
    page_icon="🌐",
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
    .news-card {
        background-color: #FFFFFF;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #e0e0e0;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
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
    .source-tag {
        background-color: #6B46C1; /* A purple color */
        color: white;
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
        font-size: 0.75rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


class UniversalAggregator:
    """
    A class to manage fetching and processing content from various sources.
    """
    def __init__(self):
        # Initialize API keys from session state or with default empty values
        if 'api_keys' not in st.session_state:
            st.session_state.api_keys = {
                'newsapi': '', 'gnews': '', 'newsdata': '', 'contextual_web': '',
                'world_news': '', 'nytimes': '', 'thenews': '', 'mediastack': '',
                'twitter_bearer': '', 'reddit_client_id': '', 'reddit_client_secret': ''
            }
        
        # Initialize RSS feeds from session state or with defaults
        if 'rss_feeds' not in st.session_state:
            st.session_state.rss_feeds = {
                'BBC News': 'http://feeds.bbci.co.uk/news/rss.xml',
                'Reuters World': 'https://www.reuters.com/investigates/rss/',
                'TechCrunch': 'https://techcrunch.com/feed/',
                'Wired': 'https://www.wired.com/feed/rss'
            }
        
        self.api_keys = st.session_state.api_keys
        self.rss_feeds = st.session_state.rss_feeds

    def _make_request(self, url, params=None, headers=None):
        """A standardized request maker with error handling."""
        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            st.warning(f"Request failed for {urlparse(url).netloc}: {e}")
            return None

    def _standardize(self, title, description, url, pub_date, source, image_url, source_type):
        """Standardizes any article into a common format."""
        return {
            'title': title,
            'description': description,
            'url': url,
            'published_at': pub_date,
            'source': source,
            'urlToImage': image_url,
            '_source_type': source_type
        }

    # --- API Fetch Methods ---
    def fetch_gnews(self, query):
        if not self.api_keys['gnews']: return []
        data = self._make_request("https://gnews.io/api/v4/search", params={'q': query, 'token': self.api_keys['gnews'], 'lang': 'en'})
        if not data: return []
        return [self._standardize(a.get('title'), a.get('description'), a.get('url'), a.get('publishedAt'), a.get('source', {}).get('name'), a.get('image'), 'GNews') for a in data.get('articles', [])]

    def fetch_mediastack(self, query):
        if not self.api_keys['mediastack']: return []
        params = {'access_key': self.api_keys['mediastack'], 'keywords': query, 'languages': 'en', 'limit': 50}
        data = self._make_request("http://api.mediastack.com/v1/news", params=params)
        if not data: return []
        return [self._standardize(a.get('title'), a.get('description'), a.get('url'), a.get('published_at'), a.get('source'), a.get('image'), 'Mediastack') for a in data.get('data', [])]

    def fetch_world_news(self, query):
        if not self.api_keys['world_news']: return []
        params = {'text': query, 'language': 'en', 'number': 50, 'api-key': self.api_keys['world_news']}
        data = self._make_request("https://api.worldnewsapi.com/search-news", params=params)
        if not data: return []
        return [self._standardize(a.get('title'), a.get('text'), a.get('url'), a.get('publish_date'), a.get('source_country'), a.get('image'), 'World News API') for a in data.get('news', [])]

    def fetch_nytimes(self, query):
        if not self.api_keys['nytimes']: return []
        params = {'q': query, 'api-key': self.api_keys['nytimes'], 'sort': 'newest'}
        data = self._make_request("https://api.nytimes.com/svc/search/v2/articlesearch.json", params=params)
        if not data: return []
        return [self._standardize(
            item.get('headline', {}).get('main'), item.get('abstract'), item.get('web_url'), item.get('pub_date'), 
            item.get('source', 'The New York Times'), 
            f"https://www.nytimes.com/{item['multimedia'][0]['url']}" if item.get('multimedia') else None, 'NY Times'
        ) for item in data.get('response', {}).get('docs', [])]

    # --- RSS Feed Method ---
    def fetch_rss(self, feed_name, feed_url, query):
        try:
            feed = feedparser.parse(feed_url)
            articles = []
            for entry in feed.entries:
                content = f"{entry.get('title', '')} {entry.get('summary', '')}".lower()
                if query.lower() in content:
                    articles.append(self._standardize(
                        entry.get('title'), entry.get('summary'), entry.get('link'), entry.get('published'), feed_name, None, 'RSS'
                    ))
            return articles
        except Exception as e:
            st.warning(f"Could not parse RSS feed '{feed_name}': {e}")
            return []

    # --- Social Media Methods ---
    def fetch_twitter(self, query):
        if not self.api_keys['twitter_bearer']: return []
        headers = {'Authorization': f"Bearer {self.api_keys['twitter_bearer']}"}
        params = {'query': f"{query} -is:retweet", 'max_results': 50, 'tweet.fields': 'created_at,public_metrics'}
        data = self._make_request("https://api.twitter.com/2/tweets/search/recent", params=params, headers=headers)
        if not data: return []
        return [self._standardize(
            item.get('text'), item.get('text'), f"https://twitter.com/any/status/{item.get('id')}",
            item.get('created_at'), 'Twitter', None, 'Twitter'
        ) for item in data.get('data', [])]

    def fetch_reddit(self, query):
        client_id = self.api_keys['reddit_client_id']
        client_secret = self.api_keys['reddit_client_secret']
        if not client_id or not client_secret: return []
        
        try:
            auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
            token_res = requests.post('https://www.reddit.com/api/v1/access_token',
                                      auth=auth, data={'grant_type': 'client_credentials'},
                                      headers={'User-Agent': 'NewsAggregator/1.0'})
            token_res.raise_for_status()
            token = token_res.json()['access_token']
            
            headers = {'Authorization': f"bearer {token}", 'User-Agent': 'NewsAggregator/1.0'}
            params = {'q': query, 'sort': 'new', 'limit': 50}
            search_res = requests.get("https://oauth.reddit.com/search", headers=headers, params=params)
            search_res.raise_for_status()
            data = search_res.json()
            
            articles = []
            for post in data.get('data', {}).get('children', []):
                p_data = post.get('data', {})
                articles.append(self._standardize(
                    p_data.get('title'), p_data.get('selftext', p_data.get('url')),
                    f"https://www.reddit.com{p_data.get('permalink', '')}",
                    datetime.fromtimestamp(p_data.get('created_utc', 0)).isoformat(),
                    f"r/{p_data.get('subreddit', 'unknown')}", p_data.get('thumbnail') if p_data.get('thumbnail') not in ['self', 'default'] else None, 'Reddit'
                ))
            return articles
        except Exception as e:
            st.warning(f"Could not fetch from Reddit: {e}")
            return []


def main():
    st.markdown('<h1 class="main-header">🌐 Universal Content Aggregator</h1>', unsafe_allow_html=True)
    aggregator = UniversalAggregator()

    # --- Sidebar UI ---
    st.sidebar.header("Dashboard Controls")

    with st.sidebar.expander("🔑 Manage Data Sources", expanded=False):
        api_tab, rss_tab, social_tab = st.tabs(["News APIs", "RSS Feeds", "Social Media"])
        with api_tab:
            for key in aggregator.api_keys:
                if 'reddit' not in key and 'twitter' not in key:
                    aggregator.api_keys[key] = st.text_input(f"{key.replace('_', ' ').title()} Key", value=aggregator.api_keys[key], type="password")
        with rss_tab:
            for name, url in list(aggregator.rss_feeds.items()):
                st.text(name)
                if st.button("❌", key=f"del_rss_{name}"):
                    del st.session_state.rss_feeds[name]
                    st.rerun()
            new_rss_name = st.text_input("New RSS Feed Name")
            new_rss_url = st.text_input("New RSS Feed URL")
            if st.button("➕ Add RSS"):
                if new_rss_name and validators.url(new_rss_url):
                    st.session_state.rss_feeds[new_rss_name] = new_rss_url
                    st.rerun()
                else:
                    st.warning("Valid name and URL required.")
        with social_tab:
            aggregator.api_keys['twitter_bearer'] = st.text_input("Twitter Bearer Token", value=aggregator.api_keys['twitter_bearer'], type="password")
            st.markdown("---")
            aggregator.api_keys['reddit_client_id'] = st.text_input("Reddit Client ID", value=aggregator.api_keys['reddit_client_id'])
            aggregator.api_keys['reddit_client_secret'] = st.text_input("Reddit Client Secret", value=aggregator.api_keys['reddit_client_secret'], type="password")

    st.sidebar.subheader("🔎 Search Parameters")
    query = st.sidebar.text_input("Search Query", "generative ai")

    # Dynamic source selection based on configured keys/feeds
    available_sources = {
        'GNews': (aggregator.fetch_gnews, aggregator.api_keys['gnews']),
        'Mediastack': (aggregator.fetch_mediastack, aggregator.api_keys['mediastack']),
        'World News API': (aggregator.fetch_world_news, aggregator.api_keys['world_news']),
        'NY Times': (aggregator.fetch_nytimes, aggregator.api_keys['nytimes']),
        'Twitter': (aggregator.fetch_twitter, aggregator.api_keys['twitter_bearer']),
        'Reddit': (aggregator.fetch_reddit, aggregator.api_keys['reddit_client_id'])
    }
    # Add configured APIs to the list
    source_options = [name for name, (_, key) in available_sources.items() if key]
    # Add RSS feeds to the list
    rss_source_options = list(aggregator.rss_feeds.keys())
    source_options.extend(rss_source_options)

    selected_sources = st.sidebar.multiselect("Choose sources to search", options=source_options, default=source_options)

    if st.sidebar.button("🔄 Fetch Content", type="primary"):
        if not query:
            st.error("Please enter a search query.")
        elif not selected_sources:
            st.error("Please select at least one source.")
        else:
            all_articles = []
            with st.spinner(f"Searching for '{query}' across {len(selected_sources)} sources..."):
                for source_name in selected_sources:
                    if source_name in available_sources: # It's an API or Social Media
                        fetch_func, _ = available_sources[source_name]
                        all_articles.extend(fetch_func(query))
                    elif source_name in aggregator.rss_feeds: # It's an RSS feed
                        feed_url = aggregator.rss_feeds[source_name]
                        all_articles.extend(aggregator.fetch_rss(source_name, feed_url, query))
                    time.sleep(0.2) # Basic rate limiting
            
            # De-duplicate results
            unique_articles = {a['title'].strip().lower(): a for a in all_articles}.values()
            st.session_state.articles = sorted(list(unique_articles), key=lambda x: x.get('published_at', '') or '1970-01-01T00:00:00Z', reverse=True)
            st.success(f"Found {len(st.session_state.articles)} unique items.")

    # --- Main Content Display ---
    if 'articles' in st.session_state and st.session_state.articles:
        st.header("📰 Unified Content Feed")
        for article in st.session_state.articles:
            with st.container(border=True):
                col1, col2 = st.columns([5, 1])
                with col1:
                    st.subheader(article['title'])
                    st.caption(f"Source: {article['source']} | Published: {article.get('published_at', 'N/A')}")
                with col2:
                    st.markdown(f"<span class='source-tag'>{article['_source_type']}</span>", unsafe_allow_html=True)

                if article.get('urlToImage'):
                    st.image(article['urlToImage'], width=250)
                
                st.write(article.get('description', 'No description available.'))
                st.link_button("Go to Source", article['url'], use_container_width=True)

if __name__ == "__main__":
    main()
