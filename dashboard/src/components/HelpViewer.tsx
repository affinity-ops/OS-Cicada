// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

type DocItem = {
    id: string;
    title: string;
    content: string;
};

type DocCategory = {
    category: string;
    docs: DocItem[];
};

type HelpViewerProps = {
    data: DocCategory[];
};

export const HelpViewer: React.FC<HelpViewerProps> = ({ data }) => {
    const [expandedCategory, setExpandedCategory] = useState<string>(data[0].category);
    const [activeDoc, setActiveDoc] = useState<DocItem>(data[0].docs[0]);

    return (
        <div className="flex flex-col lg:flex-row gap-8 min-h-[750px]">
            
            {/* Left: Accordion Navigation Panel */}
            <div className="w-full lg:w-[22rem] flex-shrink-0 flex flex-col gap-4">
                {data.map((catSection) => {
                    const isExpanded = expandedCategory === catSection.category;
                    return (
                        <div key={catSection.category} className="bg-surface-container-low rounded-2xl border border-white/5 overflow-hidden transition-all duration-300 shadow-lg">
                            <button 
                                onClick={() => setExpandedCategory(isExpanded ? '' : catSection.category)}
                                className={`w-full px-6 py-5 flex items-center justify-between transition-colors ${isExpanded ? 'bg-orange-500/10 border-b border-orange-500/10' : 'hover:bg-white/5'}`}
                            >
                                <span className={`font-headline font-bold uppercase tracking-widest text-xs ${isExpanded ? 'text-orange-500' : 'text-on-surface-variant'}`}>
                                    {catSection.category}
                                </span>
                                <span className={`material-symbols-outlined transition-transform duration-300 ${isExpanded ? 'rotate-90 text-orange-500' : 'text-neutral-500'}`}>
                                    chevron_right
                                </span>
                            </button>
                            
                            <div className={`transition-all duration-500 ease-in-out ${isExpanded ? 'max-h-[500px] opacity-100 overflow-y-auto' : 'max-h-0 opacity-0 overflow-hidden'}`}>
                                <div className="p-3 space-y-2 bg-[#0a0a0a] min-h-[100px]">
                                    {catSection.docs.map((doc) => {
                                        const isActive = activeDoc.id === doc.id;
                                        return (
                                            <button 
                                                key={doc.id}
                                                onClick={() => setActiveDoc(doc)}
                                                className={`w-full text-left px-4 py-3 rounded-xl text-sm font-body transition-all group flex items-center gap-3 ${
                                                    isActive 
                                                        ? 'bg-orange-500/10 text-orange-400 font-bold border border-orange-500/30 shadow-inner' 
                                                        : 'text-neutral-400 hover:bg-white/5 hover:text-neutral-200 border border-transparent'
                                                }`}
                                            >
                                                <span className={`material-symbols-outlined shrink-0 text-lg transition-transform ${isActive ? 'text-orange-500 scale-110' : 'text-neutral-600 group-hover:text-neutral-400'}`}>
                                                    {isActive ? 'menu_book' : 'article'}
                                                </span>
                                                <span className="leading-snug">{doc.title}</span>
                                            </button>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Right: Markdown Rendering Panel */}
            <div className="flex-1 bg-surface-container rounded-2xl border border-white/5 p-8 lg:p-14 overflow-y-auto max-h-[85vh] shadow-2xl relative">
                {activeDoc.content.includes("Documentation file not found") ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center p-8 bg-surface-container/50 backdrop-blur-sm">
                        <span className="material-symbols-outlined text-6xl text-neutral-600 mb-4">description</span>
                        <h2 className="text-xl font-headline font-bold text-neutral-300 mb-2">Document Unavailable</h2>
                        <p className="text-neutral-500 font-body text-sm max-w-md">{activeDoc.content}</p>
                    </div>
                ) : (
                    <article className="prose prose-invert max-w-4xl 
                                        prose-h1:text-4xl prose-h1:font-black prose-h1:font-headline prose-h1:tracking-tighter prose-h1:text-on-surface prose-h1:mb-8
                                        prose-h2:text-2xl prose-h2:font-bold prose-h2:font-headline prose-h2:text-neutral-100 prose-h2:border-b prose-h2:border-white/10 prose-h2:pb-3 prose-h2:mt-12
                                        prose-h3:text-xl prose-h3:font-bold prose-h3:text-neutral-200 prose-h3:mt-8
                                        prose-p:text-neutral-300 prose-p:leading-relaxed prose-p:font-body
                                        prose-a:text-orange-400 prose-a:underline-offset-4 hover:prose-a:text-orange-300
                                        prose-strong:text-neutral-100
                                        prose-code:text-orange-300 prose-code:bg-orange-500/10 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:font-technical prose-code:text-sm
                                        prose-pre:bg-[#0a0a0a] prose-pre:border prose-pre:border-white/10 prose-pre:shadow-xl prose-pre:rounded-xl
                                        prose-li:text-neutral-300 prose-ul:list-disc prose-ul:pl-6
                                        prose-blockquote:border-l-4 prose-blockquote:border-orange-500 prose-blockquote:bg-surface-container-low prose-blockquote:px-6 prose-blockquote:py-3 prose-blockquote:rounded-r-xl prose-blockquote:italic prose-blockquote:text-neutral-400 prose-blockquote:shadow-md
                                        prose-hr:border-white/10 prose-hr:my-10
                                        prose-table:w-full prose-table:border-collapse prose-th:bg-surface-container-low prose-th:font-bold prose-th:px-4 prose-th:py-3 prose-th:border prose-th:border-white/10 prose-td:px-4 prose-td:py-3 prose-td:border prose-td:border-white/5">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                            {activeDoc.content}
                        </ReactMarkdown>
                    </article>
                )}
            </div>

        </div>
    );
};
