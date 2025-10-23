#!/usr/bin/env python3
# ingest_knowledge_base.py

from pinecone import Pinecone
import requests
import os
import glob
import json
from pathlib import Path
import hashlib
from tqdm import tqdm

class KnowledgeBaseIngester:
    def __init__(self, pinecone_key, index_name='ccdc-kb'):
        self.pc = Pinecone(api_key=pinecone_key)
        self.index = self.pc.Index(index_name)
        self.ollama_url = 'https://coyotedev.ngrok.app/ollama/api/embeddings'
        self.embedding_cache = {}
        
    def get_embedding(self, text):
        """Get embedding from mxbai-embed-large with caching"""
        # Cache key
        cache_key = hashlib.md5(text.encode()).hexdigest()

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer sk-6e59f375ab2841dfbd9f9245ab6cf860',
        }

        
        if cache_key in self.embedding_cache:
            return self.embedding_cache[cache_key]
        
        response = requests.post(
            self.ollama_url,
            headers=headers,
            json={
                "model": "mxbai-embed-large",
                "prompt": text
            },
            timeout=30
        )
        
        if response.status_code == 200:
            embedding = response.json()['embedding']
            self.embedding_cache[cache_key] = embedding
            return embedding
        else:
            raise Exception(f"Embedding failed: {response.text}")
    
    def chunk_by_headers(self, content):
        """Split markdown by ## headers"""
        sections = []
        current_section = []
        
        for line in content.split('\n'):
            if line.startswith('## '):
                if current_section:
                    sections.append('\n'.join(current_section))
                current_section = [line]
            else:
                current_section.append(line)
        
        if current_section:
            sections.append('\n'.join(current_section))
        
        return sections
    
    def ingest_markdown_file(self, filepath, namespace='playbooks'):
        """Ingest a single markdown file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract title
        title = 'Untitled'
        for line in content.split('\n'):
            if line.startswith('# '):
                title = line.replace('#', '').strip()
                break
        
        # Split into sections
        sections = self.chunk_by_headers(content)
        
        vectors = []
        for idx, section in enumerate(sections):
            if len(section.strip()) < 100:  # Skip tiny sections
                continue
            
            # Generate unique ID
            doc_id = f"{Path(filepath).stem}_{idx}"
            
            # Get embedding
            try:
                embedding = self.get_embedding(section)
            except Exception as e:
                print(f"  ⚠ Failed to embed section {idx}: {e}")
                continue
            
            # Extract section title
            section_title = section.split('\n')[0].replace('#', '').strip()
            
            # Prepare metadata
            metadata = {
                'text': section[:1000],  # First 1000 chars
                'source': str(filepath),
                'filename': os.path.basename(filepath),
                'title': title,
                'section_title': section_title,
                'section_index': idx,
                'char_count': len(section),
                'namespace': namespace
            }
            
            vectors.append({
                'id': doc_id,
                'values': embedding,
                'metadata': metadata
            })
        
        # Upsert in batches of 100
        if vectors:
            batch_size = 100
            for i in range(0, len(vectors), batch_size):
                batch = vectors[i:i + batch_size]
                self.index.upsert(
                    vectors=batch,
                    namespace=namespace
                )
        
        return len(vectors)
    
    def ingest_directory(self, directory, namespace='playbooks'):
        """Ingest all markdown files from a directory"""
        if not os.path.exists(directory):
            print(f"⚠ Directory not found: {directory}")
            return 0
        
        md_files = glob.glob(f"{directory}/**/*.md", recursive=True)
        
        if not md_files:
            print(f"⚠ No markdown files found in {directory}")
            return 0
        
        print(f"\nIngesting from {directory} → namespace '{namespace}'")
        total_chunks = 0
        
        for filepath in tqdm(md_files, desc="Processing files"):
            try:
                chunks = self.ingest_markdown_file(filepath, namespace)
                total_chunks += chunks
            except Exception as e:
                print(f"\n⚠ Error processing {filepath}: {e}")
        
        print(f"✓ Ingested {len(md_files)} files, {total_chunks} chunks")
        return total_chunks
    
    def get_stats(self):
        """Get index statistics"""
        stats = self.index.describe_index_stats()
        return stats

# Usage
if __name__ == "__main__":
    import sys
    
    # Get API key from environment or prompt
    api_key = 'pcsk_4h9RDe_N9S93ASNHzqFLkGGebXmiY9QJWR5CCPMTqZSrE1tBBKPgGvgacfUv4NLZPAZSzv'
    if not api_key:
        api_key = input("Enter Pinecone API key: ").strip()
    
    if not api_key:
        print("❌ No API key provided")
        sys.exit(1)
    
    print("=== CyberSentinel Knowledge Base Ingestion ===\n")
    
    # Initialize ingester
    ingester = KnowledgeBaseIngester(pinecone_key=api_key)
    
    # Ingest different document types
    directories = {
        './just-linux/docs': 'linux-docs',
        './just-windows/docs': 'windows-docs'
    }
    
    total = 0
    for directory, namespace in directories.items():
        count = ingester.ingest_directory(directory, namespace)
        total += count
    
    # Show stats
    print("\n" + "="*50)
    print("INDEX STATISTICS")
    print("="*50)
    stats = ingester.get_stats()
    print(f"Total vectors: {stats['total_vector_count']}")
    print(f"Namespaces: {list(stats['namespaces'].keys())}")
    for ns, data in stats['namespaces'].items():
        print(f"  - {ns}: {data['vector_count']} vectors")
    
    print(f"\n✓✓✓ Ingestion complete! Total chunks: {total} ✓✓✓")
